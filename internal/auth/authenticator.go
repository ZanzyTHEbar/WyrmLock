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

	"github.com/cossacklabs/themis/gothemis/compare"
)

// Common errors
var (
	ErrAuthFailed        = errors.New("authentication failed")
	ErrSecretNotFound    = errors.New("secret not found")
	ErrTimeout           = errors.New("authentication timed out")
	ErrMaxRetries        = errors.New("max authentication retries exceeded")
)

// Default values for brute force protection
const (
	DefaultMaxAuthAttempts  = 5
	DefaultLockoutDuration  = 5 * time.Minute
)

// Authenticator provides methods for authenticating users
type Authenticator struct {
	config *config.Config
	mu     sync.Mutex

	// For ZKP using Themis
	secretData []byte

	// Optional keychain access
	keychainIntegration *keychain.KeychainIntegration
	
	// Brute force protection
	bruteForceProtection *BruteForceProtection
}

// NewAuthenticator creates a new authenticator with the given configuration
func NewAuthenticator(cfg *config.Config) (*Authenticator, error) {
	auth := &Authenticator{
		config: cfg,
		bruteForceProtection: NewBruteForceProtection(
			DefaultMaxAuthAttempts, 
			DefaultLockoutDuration,
		),
	}

	// Initialize based on configuration
	if cfg.Auth.UseZeroKnowledgeProof {
		// Check if we should use keychain
		if cfg.KeychainService != "" && cfg.KeychainAccount != "" {
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
		} else if cfg.Auth.SecretPath != "" {
			// Read secret from file
			data, err := os.ReadFile(cfg.Auth.SecretPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read secret file: %w", err)
			}

			auth.secretData = data
		} else {
			return nil, errors.New("no secret source configured")
		}
	} else {
		// Traditional password hashing is implemented in a separate method
		// We'll check configuration here
		if cfg.Auth.HashAlgorithm == "" {
			return nil, errors.New("hash algorithm must be specified when not using ZKP")
		}
	}

	return auth, nil
}

// AuthenticateZKP authenticates a user using zero-knowledge proof with Themis
func (a *Authenticator) AuthenticateZKP(userInput []byte) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Create a context with timeout for the authentication process
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get the stored secret
	secret, err := a.getSecret()
	if err != nil {
		return false, fmt.Errorf("failed to get secret: %w", err)
	}

	// Create a secure comparator for the server side
	serverComparator, err := compare.New()
	if err != nil {
		return false, fmt.Errorf("failed to create server comparator: %w", err)
	}

	// Create a secure comparator for the client side
	clientComparator, err := compare.New()
	if err != nil {
		return false, fmt.Errorf("failed to create client comparator: %w", err)
	}

	// Set the secrets for both sides
	if err := serverComparator.Append(secret); err != nil {
		return false, fmt.Errorf("failed to set server secret: %w", err)
	}

	if err := clientComparator.Append(userInput); err != nil {
		return false, fmt.Errorf("failed to set client secret: %w", err)
	}

	// Run the secure comparison protocol
	var clientData, serverData []byte
	var err1, err2 error

	// Initial message from client
	clientData, err1 = clientComparator.Begin()
	if err1 != nil {
		return false, fmt.Errorf("failed to begin comparison: %w", err1)
	}

	// Continue the protocol until it's completed
	inProgress := true
	maxIterations := 10 // Prevent infinite loops
	iterations := 0
	
	for inProgress {
		// Check for timeout or too many iterations
		if iterations >= maxIterations {
			return false, ErrMaxRetries
		}
		
		select {
		case <-ctx.Done():
			return false, ErrTimeout
		default:
			// Continue with the protocol
		}
		
		serverData, err2 = serverComparator.Proceed(clientData)
		if err2 != nil {
			return false, fmt.Errorf("server comparison failed: %w", err2)
		}

		// Check if we're done
		serverResult, err := serverComparator.Result()
		if err != nil {
			return false, fmt.Errorf("failed to get server result: %w", err)
		}

		if serverResult == compare.Match {
			return true, nil
		}

		if serverResult == compare.NoMatch {
			return false, nil
		}

		// If not done, continue the protocol
		clientData, err1 = clientComparator.Proceed(serverData)
		if err1 != nil {
			return false, fmt.Errorf("client comparison failed: %w", err1)
		}

		// Check if we're done
		clientResult, err := clientComparator.Result()
		if err != nil {
			return false, fmt.Errorf("failed to get client result: %w", err)
		}

		if clientResult == compare.Match {
			return true, nil
		}

		if clientResult == compare.NoMatch {
			return false, nil
		}

		// If we got here, we need to continue the protocol
		inProgress = (clientResult == compare.NotReady)
		iterations++
	}

	// We shouldn't reach here, but just in case
	return false, errors.New("comparison protocol ended unexpectedly")
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
func ClearMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
