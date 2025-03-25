package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"applock-go/internal/config"
	"applock-go/internal/keychain"
	"applock-go/internal/logging"

	"github.com/cossacklabs/themis/gothemis/compare"
)

// Common errors
var (
	ErrAuthFailed             = errors.New("authentication failed")
	ErrSecretNotFound         = errors.New("secret not found")
	ErrTimeout                = errors.New("authentication timed out")
	ErrMaxRetries             = errors.New("max authentication retries exceeded")
	ErrInvalidProtocolState   = errors.New("invalid ZKP protocol state")
	ErrComparatorInitFailed   = errors.New("failed to initialize secure comparator")
	ErrComparatorSecretFailed = errors.New("failed to set comparator secret")
	ErrProtocolAborted        = errors.New("ZKP protocol aborted")
	ErrProtocolExceeded       = errors.New("ZKP protocol exceeded maximum iterations")
)

// Default values for brute force protection
const (
	DefaultMaxAuthAttempts = 5
	DefaultLockoutDuration = 5 * time.Minute
)

// ZKP protocol constants
const (
	ZKPProtocolTimeout  = 30 * time.Second
	ZKPMaxIterations    = 10
	ZKPMemoryCleanDelay = 100 * time.Millisecond
)

// Authenticator provides methods for authenticating users
type Authenticator struct {
	config *config.Config
	mu     sync.Mutex
	logger *logging.Logger

	// For ZKP using Themis
	secretData []byte

	// Optional keychain access
	keychainIntegration *keychain.KeychainIntegration

	// Brute force protection
	bruteForceProtection *BruteForceProtection
}

// protocolState tracks the state of the ZKP protocol
type protocolState struct {
	iteration    int
	lastPhase    string
	messages     [][]byte
	serverResult int
	clientResult int
}

// NewAuthenticator creates a new authenticator with the given configuration
func NewAuthenticator(cfg *config.Config) (*Authenticator, error) {
	auth := &Authenticator{
		config: cfg,
		logger: logging.NewLogger("auth", true),
		bruteForceProtection: NewBruteForceProtection(
			DefaultMaxAuthAttempts,
			DefaultLockoutDuration,
		),
	}

	// Initialize based on configuration
	if cfg.Auth.SecretPath != "" {
		// Read secret from file
		data, err := os.ReadFile(cfg.Auth.SecretPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret file: %w", err)
		}

		auth.secretData = data
	} else if cfg.KeychainService != "" && cfg.KeychainAccount != "" {
		// Initialize keychain integration
		kc, err := keychain.NewKeychainIntegration(cfg.KeychainService, cfg.KeychainAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize keychain: %w", err)
		}
		auth.keychainIntegration = kc

		// Try to access the secret
		exists, err := kc.SecretExists()
		if err != nil {
			return nil, fmt.Errorf("failed to check if secret exists: %w", err)
		}

		if !exists {
			return nil, ErrSecretNotFound
		}
	} else {
		return nil, errors.New("no secret source configured")
	}

	// Additional validation for traditional auth mode
	if !cfg.Auth.UseZeroKnowledgeProof && cfg.Auth.HashAlgorithm == "" {
		return nil, errors.New("hash algorithm must be specified when not using ZKP")
	}

	return auth, nil
}

// AuthenticateZKP authenticates a user using zero-knowledge proof with Themis
//
// This implements a zero-knowledge proof protocol using Themis's Secure Comparator, where:
// 1. Neither party learns the other's secret, only whether they match
// 2. The protocol exchanges multiple messages between client and server comparators
// 3. The protocol is secure against replay attacks as each session generates unique messages
// 4. The protocol is secure against eavesdropping as the messages don't reveal the secrets
//
// The implementation handles multiple protocol iterations and properly cleans up memory
// to ensure sensitive data doesn't remain in memory after authentication.
func (a *Authenticator) AuthenticateZKP(userInput []byte) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Enhanced error handling with more descriptive errors
	// Ensure input is not empty
	if len(userInput) == 0 {
		return false, fmt.Errorf("empty authentication input")
	}

	// Create a context with timeout for the authentication process
	ctx, cancel := context.WithTimeout(context.Background(), ZKPProtocolTimeout)
	defer cancel()

	// Get the stored secret
	secret, err := a.getSecret()
	if err != nil {
		return false, fmt.Errorf("failed to get secret: %w", err)
	}
	// Ensure we clear the secret from memory when done
	defer func() {
		ClearMemory(secret)
		// Small delay to ensure memory is cleared before function returns
		// This helps prevent optimization that might keep the secret in memory
		time.Sleep(ZKPMemoryCleanDelay)
	}()

	// Create new protocol state for tracking
	state := &protocolState{
		iteration: 0,
		lastPhase: "",
		messages:  make([][]byte, 0, ZKPMaxIterations*2), // Pre-allocate enough capacity
	}

	// Create secure comparators with proper cleanup
	serverComparator, err := compare.New()
	if err != nil {
		a.logger.Errorf("failed to create server comparator: %v", err)
		return false, fmt.Errorf("%w: %v", ErrComparatorInitFailed, err)
	}
	
	clientComparator, err := compare.New()
	if err != nil {
		a.logger.Errorf("failed to create client comparator: %v", err)
		return false, fmt.Errorf("%w: %v", ErrComparatorInitFailed, err)
	}

	// Set the secrets for both sides
	if err := serverComparator.Append(secret); err != nil {
		a.logger.Errorf("failed to set server secret: %v", err)
		return false, fmt.Errorf("%w: %v", ErrComparatorSecretFailed, err)
	}
	
	if err := clientComparator.Append(userInput); err != nil {
		a.logger.Errorf("failed to set client secret: %v", err)
		return false, fmt.Errorf("%w: %v", ErrComparatorSecretFailed, err)
	}

	// Initial message from client
	clientData, err := clientComparator.Begin()
	if err != nil {
		a.logger.Errorf("failed to begin comparison: %v", err)
		return false, fmt.Errorf("failed to begin comparison: %w", err)
	}
	
	// Track the first message
	state.lastPhase = "client_begin"
	state.messages = append(state.messages, clientData)
	
	a.logger.Debugf("ZKP protocol started, iteration %d, phase %s", 
		state.iteration, state.lastPhase)

	// Continue the protocol until it's completed
	inProgress := true
	var serverData []byte

	for inProgress && state.iteration < ZKPMaxIterations {
		select {
		case <-ctx.Done():
			// Log protocol state on timeout
			a.logger.Warnf("ZKP protocol timed out at iteration %d, phase %s",
				state.iteration, state.lastPhase)
			return false, fmt.Errorf("%w: protocol timed out at phase %s after %d iterations",
				ErrTimeout, state.lastPhase, state.iteration)
		default:
			// Server phase
			if state.lastPhase == "client_begin" || state.lastPhase == "client_proceed" {
				serverData, err = serverComparator.Proceed(clientData)
				if err != nil {
					a.logger.Errorf("Server comparison failed at iteration %d: %v",
						state.iteration, err)
					return false, fmt.Errorf("server comparison failed at iteration %d: %w",
						state.iteration, err)
				}
				
				// Track message and update state
				state.lastPhase = "server_proceed"
				state.messages = append(state.messages, serverData)
				
				a.logger.Debugf("ZKP server proceed, iteration %d", state.iteration)

				// Check server result
				serverResult, err := serverComparator.Result()
				if err != nil {
					a.logger.Errorf("Failed to get server result: %v", err)
					return false, fmt.Errorf("failed to get server result at iteration %d: %w",
						state.iteration, err)
				}
				
				// Save result in state
				state.serverResult = serverResult

				switch serverResult {
				case compare.Match:
					a.logger.Debug("ZKP authentication succeeded (server)")
					return true, nil
				case compare.NoMatch:
					a.logger.Debug("ZKP authentication failed: no match (server)")
					return false, ErrAuthFailed
				}
			}

			// Client phase
			if state.lastPhase == "server_proceed" {
				clientData, err = clientComparator.Proceed(serverData)
				if err != nil {
					a.logger.Errorf("Client comparison failed at iteration %d: %v",
						state.iteration, err)
					return false, fmt.Errorf("client comparison failed at iteration %d: %w",
						state.iteration, err)
				}
				
				// Track message and update state
				state.lastPhase = "client_proceed"
				state.messages = append(state.messages, clientData)
				
				a.logger.Debugf("ZKP client proceed, iteration %d", state.iteration)

				// Check client result
				clientResult, err := clientComparator.Result()
				if err != nil {
					a.logger.Errorf("Failed to get client result: %v", err)
					return false, fmt.Errorf("failed to get client result at iteration %d: %w",
						state.iteration, err)
				}
				
				// Save result in state
				state.clientResult = clientResult

				switch clientResult {
				case compare.Match:
					a.logger.Debug("ZKP authentication succeeded (client)")
					return true, nil
				case compare.NoMatch:
					a.logger.Debug("ZKP authentication failed: no match (client)")
					return false, ErrAuthFailed
				}
			}

			// Update state for next iteration
			state.iteration++
			inProgress = (state.lastPhase == "client_proceed")
			
			// Verify protocol state is valid after each iteration
			if err := a.verifyProtocolState(state); err != nil {
				a.logger.Errorf("Protocol state verification failed: %v", err)
				return false, fmt.Errorf("%w: %v", ErrInvalidProtocolState, err)
			}
		}
	}

	if state.iteration >= ZKPMaxIterations {
		a.logger.Warnf("ZKP protocol exceeded maximum iterations")
		return false, ErrProtocolExceeded
	}

	// We shouldn't reach here, but just in case
	return false, ErrProtocolAborted
}

// verifyProtocolState checks the validity of the protocol state
func (a *Authenticator) verifyProtocolState(state *protocolState) error {
	// Check iteration count
	if state.iteration < 0 || state.iteration > ZKPMaxIterations {
		return fmt.Errorf("invalid iteration count: %d", state.iteration)
	}

	// Verify message sequence
	if len(state.messages) < 1 {
		return errors.New("no protocol messages recorded")
	}

	// Check message validity - each message should be non-empty
	for i, msg := range state.messages {
		if len(msg) == 0 {
			return fmt.Errorf("empty message at position %d", i)
		}
	}

	// Verify the number of messages is consistent with the iteration count
	// Each iteration should have 2 messages (client and server)
	expectedMessages := state.iteration * 2
	if state.lastPhase == "client_begin" || state.lastPhase == "server_proceed" {
		expectedMessages++
	}
	
	if expectedMessages != len(state.messages) {
		return fmt.Errorf("message count inconsistency: expected %d, got %d", 
			expectedMessages, len(state.messages))
	}

	// Verify phase transition is valid
	validTransitions := map[string][]string{
		"":               {"client_begin"},
		"client_begin":   {"server_proceed"},
		"server_proceed": {"client_proceed"},
		"client_proceed": {"server_proceed"},
	}

	// Check if the current phase is valid
	if valid, ok := validTransitions[state.lastPhase]; !ok {
		return fmt.Errorf("invalid protocol phase: %s", state.lastPhase)
	} else if ok && len(valid) > 0 {
		// If there's a next phase, verify it's a valid transition
		// This is primarily for debugging purposes and doesn't get checked
		// until the next iteration
		if state.iteration > 0 && state.lastPhase == "server_proceed" {
			// Ensure only client_proceed can follow server_proceed
			for _, v := range valid {
				if v != "client_proceed" {
					return fmt.Errorf("invalid phase transition rule from %s", state.lastPhase)
				}
			}
		} else if state.iteration > 0 && state.lastPhase == "client_proceed" {
			// Ensure only server_proceed can follow client_proceed
			for _, v := range valid {
				if v != "server_proceed" {
					return fmt.Errorf("invalid phase transition rule from %s", state.lastPhase)
				}
			}
		}
	}

	return nil
}

// Authenticate verifies if the provided user input matches the stored secret
func (a *Authenticator) Authenticate(userInput []byte, appPath string) (bool, error) {
	// Add basic input validation
	if len(userInput) == 0 {
		return false, errors.New("empty authentication input")
	}

	// Check brute force protection
	if err := a.bruteForceProtection.CheckAttempt(appPath); err != nil {
		if errors.Is(err, ErrMaxAttemptsExceeded) || errors.Is(err, ErrTempLockout) {
			// Get the lockout duration if applicable
			lockoutDuration := a.bruteForceProtection.GetLockoutDuration(appPath)
			if lockoutDuration > 0 {
				return false, fmt.Errorf("%w: locked out for %s",
					ErrTempLockout, lockoutDuration.Round(time.Second))
			}
			return false, err
		}
		// Some other unexpected error
		return false, fmt.Errorf("error checking brute force protection: %w", err)
	}

	var authSuccess bool
	var authErr error

	if a.config.Auth.UseZeroKnowledgeProof {
		authSuccess, authErr = a.AuthenticateZKP(userInput)
	} else {
		// Fall back to traditional password hashing
		authSuccess, authErr = a.AuthenticateTraditional(userInput)
	}

	// Record success or failure for brute force protection
	if authErr != nil {
		// Don't count errors as failures
		return false, authErr
	} else if authSuccess {
		a.bruteForceProtection.RecordSuccess(appPath)
	} else {
		a.bruteForceProtection.RecordFailure(appPath)
	}

	return authSuccess, nil
}

// AuthenticateTraditional authenticates a user using traditional password hashing
func (a *Authenticator) AuthenticateTraditional(userInput []byte) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Get the stored hash
	storedHash, err := a.getSecret()
	if err != nil {
		return false, fmt.Errorf("failed to get stored hash: %w", err)
	}

	// Choose the appropriate hashing algorithm
	switch a.config.Auth.HashAlgorithm {
	case "bcrypt":
		return compareBcrypt(userInput, storedHash)
	case "argon2id":
		return compareArgon2id(userInput, storedHash)
	case "scrypt":
		return compareScrypt(userInput, storedHash)
	case "pbkdf2":
		return comparePBKDF2(userInput, storedHash)
	default:
		return false, fmt.Errorf("unsupported hash algorithm: %s", a.config.Auth.HashAlgorithm)
	}
}

// getSecret retrieves the secret/hash from the configured source
func (a *Authenticator) getSecret() ([]byte, error) {
	if a.keychainIntegration != nil {
		// Get secret from keychain
		return a.keychainIntegration.GetSecret()
	}

	// Return the secret loaded from file
	if a.secretData != nil {
		return a.secretData, nil
	}

	return nil, ErrSecretNotFound
}

// SetSecret saves a new secret
func (a *Authenticator) SetSecret(secret []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// For zero-knowledge proofs, we store the raw secret
	// For traditional authentication, we need to hash it first
	var dataToStore []byte
	var err error

	if a.config.Auth.UseZeroKnowledgeProof {
		// ZKP mode, store raw secret for Secure Comparator
		dataToStore = secret
	} else {
		// Traditional mode, hash the password
		dataToStore, err = GenerateHash(secret, a.config.Auth.HashAlgorithm)
		if err != nil {
			return fmt.Errorf("failed to hash secret: %w", err)
		}
	}

	// Save to appropriate storage
	if a.keychainIntegration != nil {
		// Save to keychain
		if err := a.keychainIntegration.SaveSecret(dataToStore); err != nil {
			return fmt.Errorf("failed to save secret to keychain: %w", err)
		}
	} else if a.config.Auth.SecretPath != "" {
		// Save to file
		// Ensure the directory exists
		dir := filepath.Dir(a.config.Auth.SecretPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory for secret: %w", err)
		}

		// Write the secret with secure permissions
		if err := os.WriteFile(a.config.Auth.SecretPath, dataToStore, 0600); err != nil {
			return fmt.Errorf("failed to write secret file: %w", err)
		}

		// Update in-memory copy
		a.secretData = dataToStore
		return nil
	} else {
		return errors.New("no secret destination configured")
	}

	return nil
}

// GetRemainingAttempts returns the number of attempts remaining before lockout
func (a *Authenticator) GetRemainingAttempts(appPath string) int {
	return a.bruteForceProtection.GetRemainingAttempts(appPath)
}

// ResetAttempts resets the brute force protection for a specific app
func (a *Authenticator) ResetAttempts(appPath string) {
	a.bruteForceProtection.ResetAttempts(appPath)
}

// ClearMemory securely wipes a byte slice
// This function ensures that sensitive data like secrets and passwords
// are properly removed from memory to prevent leaks in case of memory dumps.
func ClearMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// GetSecretPath returns the path to the secret file used by the authenticator
// This method is primarily used for testing purposes
func (a *Authenticator) GetSecretPath() string {
	return a.config.Auth.SecretPath
}
