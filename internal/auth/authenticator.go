package auth

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"wyrmlock/internal/config"
	"wyrmlock/internal/keychain"
	"wyrmlock/internal/logging"

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
	ErrEmptyInput             = errors.New("empty authentication input")
	ErrMemoryCompromised      = errors.New("memory integrity check failed")
	ErrInvalidComparatorState = errors.New("invalid secure comparator state")
)

// Default values for brute force protection
const (
	DefaultMaxAuthAttempts = 5
	DefaultLockoutDuration = 5 * time.Minute
)

// ZKP protocol constants
const (
	ZKPProtocolTimeout       = 30 * time.Second
	ZKPMaxIterations         = 10
	ZKPMemoryCleanDelay      = 100 * time.Millisecond
	ZKPMemoryCleanIterations = 3 // Multiple overwrite iterations
)

// ZKP result constants from Themis secure comparator
const (
	ZKPResultNotReady = iota
	ZKPResultNoMatch
	ZKPResultMatch
	ZKPResultInProgress // Match Themis's internal state
)

// ZKP phase constants
const (
	ZKPPhaseInitial        = "initial"
	ZKPPhaseClientBegin    = "client_begin"
	ZKPPhaseServerProceed  = "server_proceed"
	ZKPPhaseClientProceed  = "client_proceed"
	ZKPPhaseCompleted      = "completed"
	ZKPPhaseFailed         = "failed"
	ZKPPhaseTimeout        = "timeout"
	ZKPPhaseInvalid        = "invalid"
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
	iteration    int                 // Current iteration
	lastPhase    string              // Last completed phase
	messages     [][]byte            // Message history
	serverResult int                 // Server comparison result
	clientResult int                 // Client comparison result
	startTime    time.Time           // When the protocol started
	lastActive   time.Time           // When the protocol was last active
	contextID    string              // Unique ID for this protocol run
	metadata     map[string]string   // Additional metadata for debugging
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
		return false, ErrEmptyInput
	}

	// Create a context with timeout for the authentication process
	ctx, cancel := context.WithTimeout(context.Background(), ZKPProtocolTimeout)
	defer cancel()

	// Create new protocol state for tracking
	state := &protocolState{
		iteration:  0,
		lastPhase:  ZKPPhaseInitial,
		messages:   make([][]byte, 0, ZKPMaxIterations*2), // Pre-allocate enough capacity
		startTime:  time.Now(),
		lastActive: time.Now(),
		contextID:  generateProtocolID(),
		metadata:   make(map[string]string),
	}

	// Add basic tracking info
	state.metadata["client_ip"] = "local" // In a networked context, this would be the client IP
	state.metadata["auth_type"] = "zkp_secure_comparator"
	state.metadata["user_agent"] = "wyrmlock" // Could be more specific in a real context

	// Log protocol initiation with context ID for tracing
	a.logger.Debugf("Starting ZKP protocol with context ID: %s", state.contextID)

	// Get the stored secret with secure handling
	secret, err := a.getSecret()
	if err != nil {
		return false, fmt.Errorf("failed to get secret: %w", err)
	}
	
	// Ensure we clear the secret from memory when done with multiple overwrite passes
	defer func() {
		// Multiple cleaning passes for secure memory wiping
		for i := 0; i < ZKPMemoryCleanIterations; i++ {
			ClearMemory(secret)
		}
		// Add a memory barrier to prevent compiler optimizations that might keep data in registers
		runtime.KeepAlive(secret)
		// Small delay to ensure memory is cleared before function returns
		time.Sleep(ZKPMemoryCleanDelay)
	}()

	// Verify secret is valid
	if len(secret) == 0 {
		return false, fmt.Errorf("%w: stored secret is empty", ErrSecretNotFound)
	}

	// Create secure comparators with proper error handling
	serverComparator, clientComparator, err := a.createComparators(secret, userInput)
	if err != nil {
		return false, err
	}

	// Start the protocol
	success, err := a.runZKPProtocol(ctx, state, serverComparator, clientComparator)
	
	// Complete metadata for audit logging
	state.metadata["duration"] = fmt.Sprintf("%v", time.Since(state.startTime))
	state.metadata["iterations"] = fmt.Sprintf("%d", state.iteration)
	state.metadata["result"] = fmt.Sprintf("%v", success)
	if err != nil {
		state.metadata["error"] = err.Error()
	}
	
	// Log completion info
	if success {
		a.logger.Infof("ZKP protocol %s succeeded after %d iterations in %v", 
			state.contextID, state.iteration, time.Since(state.startTime))
	} else {
		a.logger.Infof("ZKP protocol %s failed after %d iterations in %v: %v", 
			state.contextID, state.iteration, time.Since(state.startTime), err)
	}
	
	return success, err
}

// createComparators creates and initializes the secure comparators for ZKP
func (a *Authenticator) createComparators(secret, userInput []byte) (*compare.SecureCompare, *compare.SecureCompare, error) {
	// Create the server comparator
	serverComparator, err := compare.New()
	if err != nil {
		a.logger.Errorf("failed to create server comparator: %v", err)
		return nil, nil, fmt.Errorf("%w: %v", ErrComparatorInitFailed, err)
	}
	
	// Create the client comparator
	clientComparator, err := compare.New()
	if err != nil {
		a.logger.Errorf("failed to create client comparator: %v", err)
		return nil, nil, fmt.Errorf("%w: %v", ErrComparatorInitFailed, err)
	}

	// Set the secrets for both sides with error handling
	if err := serverComparator.Append(secret); err != nil {
		a.logger.Errorf("failed to set server secret: %v", err)
		return nil, nil, fmt.Errorf("%w: %v", ErrComparatorSecretFailed, err)
	}
	
	if err := clientComparator.Append(userInput); err != nil {
		a.logger.Errorf("failed to set client secret: %v", err)
		return nil, nil, fmt.Errorf("%w: %v", ErrComparatorSecretFailed, err)
	}
	
	return serverComparator, clientComparator, nil
}

// runZKPProtocol executes the ZKP protocol state machine
func (a *Authenticator) runZKPProtocol(
	ctx context.Context,
	state *protocolState,
	serverComparator *compare.SecureCompare,
	clientComparator *compare.SecureCompare,
) (bool, error) {
	// Initial message from client to start the protocol
	clientData, err := clientComparator.Begin()
	if err != nil {
		a.logger.Errorf("failed to begin comparison: %v", err)
		state.lastPhase = ZKPPhaseFailed
		return false, fmt.Errorf("failed to begin comparison: %w", err)
	}
	
	// Track the first message
	state.lastPhase = ZKPPhaseClientBegin
	state.messages = append(state.messages, clientData)
	state.lastActive = time.Now()
	
	a.logger.Debugf("ZKP protocol started (ctx: %s), iteration %d, phase %s", 
		state.contextID, state.iteration, state.lastPhase)

	// Continue the protocol until it's completed
	inProgress := true
	var serverData []byte

	for inProgress && state.iteration < ZKPMaxIterations {
		select {
		case <-ctx.Done():
			// Log protocol state on timeout
			a.logger.Warnf("ZKP protocol %s timed out at iteration %d, phase %s",
				state.contextID, state.iteration, state.lastPhase)
			state.lastPhase = ZKPPhaseTimeout
			return false, fmt.Errorf("%w: protocol timed out at phase %s after %d iterations",
				ErrTimeout, state.lastPhase, state.iteration)
		default:
			// Server phase - process the client's message
			if state.lastPhase == ZKPPhaseClientBegin || state.lastPhase == ZKPPhaseClientProceed {
				// Process the client's message on the server side
				serverData, err = serverComparator.Proceed(clientData)
				if err != nil {
					a.logger.Errorf("Server comparison failed at iteration %d: %v",
						state.iteration, err)
					state.lastPhase = ZKPPhaseFailed
					return false, fmt.Errorf("server comparison failed at iteration %d: %w",
						state.iteration, err)
				}
				
				// Track message and update state
				state.lastPhase = ZKPPhaseServerProceed
				state.messages = append(state.messages, serverData)
				state.lastActive = time.Now()
				
				a.logger.Debugf("ZKP server proceed (ctx: %s), iteration %d", 
					state.contextID, state.iteration)

				// Check server result
				serverResult, err := serverComparator.Result()
				if err != nil {
					a.logger.Errorf("Failed to get server result: %v", err)
					state.lastPhase = ZKPPhaseFailed
					return false, fmt.Errorf("failed to get server result at iteration %d: %w",
						state.iteration, err)
				}
				
				// Save result in state
				state.serverResult = serverResult

				// Handle completed protocol from server side
				if serverResult == compare.Match {
					a.logger.Debugf("ZKP authentication succeeded (server) (ctx: %s)", state.contextID)
					state.lastPhase = ZKPPhaseCompleted
					return true, nil
				} else if serverResult == compare.NoMatch {
					a.logger.Debugf("ZKP authentication failed: no match (server) (ctx: %s)", state.contextID)
					state.lastPhase = ZKPPhaseCompleted
					return false, ErrAuthFailed
				}
			}

			// Client phase - process the server's response
			if state.lastPhase == ZKPPhaseServerProceed {
				// Process the server's message on the client side
				clientData, err = clientComparator.Proceed(serverData)
				if err != nil {
					a.logger.Errorf("Client comparison failed at iteration %d: %v",
						state.iteration, err)
					state.lastPhase = ZKPPhaseFailed
					return false, fmt.Errorf("client comparison failed at iteration %d: %w",
						state.iteration, err)
				}
				
				// Track message and update state
				state.lastPhase = ZKPPhaseClientProceed
				state.messages = append(state.messages, clientData)
				state.lastActive = time.Now()
				
				a.logger.Debugf("ZKP client proceed (ctx: %s), iteration %d",
					state.contextID, state.iteration)

				// Check client result
				clientResult, err := clientComparator.Result()
				if err != nil {
					a.logger.Errorf("Failed to get client result: %v", err)
					state.lastPhase = ZKPPhaseFailed
					return false, fmt.Errorf("failed to get client result at iteration %d: %w",
						state.iteration, err)
				}
				
				// Save result in state
				state.clientResult = clientResult

				// Handle completed protocol from client side
				if clientResult == compare.Match {
					a.logger.Debugf("ZKP authentication succeeded (client) (ctx: %s)", state.contextID)
					state.lastPhase = ZKPPhaseCompleted
					return true, nil
				} else if clientResult == compare.NoMatch {
					a.logger.Debugf("ZKP authentication failed: no match (client) (ctx: %s)", state.contextID)
					state.lastPhase = ZKPPhaseCompleted
					return false, ErrAuthFailed
				}
			}

			// Update state for next iteration
			state.iteration++
			inProgress = (state.lastPhase == ZKPPhaseClientProceed)
			
			// Verify protocol state is valid after each iteration
			if err := a.verifyProtocolState(state); err != nil {
				a.logger.Errorf("Protocol state verification failed: %v", err)
				state.lastPhase = ZKPPhaseInvalid
				return false, fmt.Errorf("%w: %v", ErrInvalidProtocolState, err)
			}
		}
	}

	// Check if we exceeded max iterations
	if state.iteration >= ZKPMaxIterations {
		a.logger.Warnf("ZKP protocol %s exceeded maximum iterations", state.contextID)
		state.lastPhase = ZKPPhaseFailed
		return false, ErrProtocolExceeded
	}

	// This should be unreachable, but just in case
	a.logger.Warnf("ZKP protocol %s aborted unexpectedly", state.contextID)
	state.lastPhase = ZKPPhaseFailed
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
	if state.lastPhase == ZKPPhaseClientBegin || state.lastPhase == ZKPPhaseServerProceed {
		expectedMessages++
	}
	
	if expectedMessages != len(state.messages) {
		return fmt.Errorf("message count inconsistency: expected %d, got %d", 
			expectedMessages, len(state.messages))
	}

	// Verify phase transition is valid
	validTransitions := map[string][]string{
		ZKPPhaseInitial:       {ZKPPhaseClientBegin},
		ZKPPhaseClientBegin:   {ZKPPhaseServerProceed},
		ZKPPhaseServerProceed: {ZKPPhaseClientProceed, ZKPPhaseCompleted},
		ZKPPhaseClientProceed: {ZKPPhaseServerProceed, ZKPPhaseCompleted},
		ZKPPhaseCompleted:     {},
		ZKPPhaseFailed:        {},
		ZKPPhaseTimeout:       {},
		ZKPPhaseInvalid:       {},
	}

	// Check if the current phase is valid
	if valid, ok := validTransitions[state.lastPhase]; !ok {
		return fmt.Errorf("invalid protocol phase: %s", state.lastPhase)
	} else if ok && len(valid) > 0 {
		// Verification here is just to ensure the protocol state is valid
		// during the protocol execution, not to predict the next state
		if state.lastPhase == ZKPPhaseServerProceed && 
		   state.serverResult != ZKPResultNotReady && 
		   state.serverResult != ZKPResultInProgress {
			// Check if the server has a definitive result
			if state.serverResult != compare.Match && state.serverResult != compare.NoMatch {
				return fmt.Errorf("invalid server result: %d", state.serverResult)
			}
		} else if state.lastPhase == ZKPPhaseClientProceed &&
				 state.clientResult != ZKPResultNotReady && 
				 state.clientResult != ZKPResultInProgress {
			// Check if the client has a definitive result
			if state.clientResult != compare.Match && state.clientResult != compare.NoMatch {
				return fmt.Errorf("invalid client result: %d", state.clientResult)
			}
		}
	}

	// Check for timeout - this is a sanity check in addition to the context timeout
	if time.Since(state.lastActive) > ZKPProtocolTimeout {
		return fmt.Errorf("protocol inactive for too long: %v", time.Since(state.lastActive))
	}

	return nil
}

// generateProtocolID creates a unique identifier for a protocol session
func generateProtocolID() string {
	// Generate a random ID for protocol tracing
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp if random generation fails
		return fmt.Sprintf("zkp-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("zkp-%x", b)
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
	// Use memory barrier to prevent optimization
	runtime.KeepAlive(data)
	
	// Fill with random data first
	_, err := rand.Read(data)
	if err != nil {
		// If random fill fails, use alternating bit patterns
		for i := range data {
			data[i] = byte(i & 0xFF)
		}
	}
	
	// Then zero it out
	for i := range data {
		data[i] = 0
	}
	
	// Use memory barrier again
	runtime.KeepAlive(data)
}

// GetSecretPath returns the path to the secret file used by the authenticator
// This method is primarily used for testing purposes
func (a *Authenticator) GetSecretPath() string {
	return a.config.Auth.SecretPath
}
