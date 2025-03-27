package keychain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

var (
	// Common errors
	ErrSecretNotFound = errors.New("secret not found in keychain")
	ErrServiceUnavailable = errors.New("keychain service is unavailable")
)

// KeychainIntegration handles interactions with the system keyring (cross-platform)
type KeychainIntegration struct {
	// Service and account names for the keychain items
	service string
	account string
	
	// Fallback file path if keychain is unavailable
	fallbackPath string
	
	// Mutex for thread safety
	mu sync.Mutex
	
	// Track if we're using fallback mode
	usingFallback bool
}

// NewKeychainIntegration creates a new keychain integration
func NewKeychainIntegration(service, account string) (*KeychainIntegration, error) {
	if service == "" || account == "" {
		return nil, errors.New("service and account names cannot be empty")
	}
	
	// Create default fallback path in user's home directory
	homeDir, err := os.UserHomeDir()
	fallbackPath := filepath.Join(homeDir, ".config", "wyrmlock", "secret")
	if err != nil {
		// If we can't get home directory, use /tmp as a last resort
		fallbackPath = "/tmp/wyrmlock-secret"
	}
	
	return &KeychainIntegration{
		service: service,
		account: account,
		fallbackPath: fallbackPath,
	}, nil
}

// WithFallbackPath sets a custom fallback path
func (k *KeychainIntegration) WithFallbackPath(path string) *KeychainIntegration {
	k.mu.Lock()
	defer k.mu.Unlock()
	
	k.fallbackPath = path
	return k
}

// IsUsingFallback returns true if the keychain is using fallback storage
func (k *KeychainIntegration) IsUsingFallback() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	
	return k.usingFallback
}

// SecretExists checks if a secret exists in the keychain
func (k *KeychainIntegration) SecretExists() (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	
	// Try keychain first
	_, err := keyring.Get(k.service, k.account)
	if err == nil {
		k.usingFallback = false
		return true, nil
	}
	
	// Check if it's a "secret not found" error
	if err == keyring.ErrNotFound {
		k.usingFallback = false
		return false, nil
	}
	
	// If keychain is unavailable, check fallback file
	if k.fallbackPath != "" {
		if _, statErr := os.Stat(k.fallbackPath); statErr == nil {
			k.usingFallback = true
			return true, nil
		}
	}
	
	// No secret found in keychain or fallback
	return false, nil
}

// GetSecret retrieves a secret from the keychain
func (k *KeychainIntegration) GetSecret() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	
	// Try keychain first
	secret, err := keyring.Get(k.service, k.account)
	if err == nil {
		k.usingFallback = false
		// Try to decode base64 first, fallback to raw bytes if not valid base64
		decoded, decodeErr := base64.StdEncoding.DecodeString(secret)
		if decodeErr == nil {
			return decoded, nil
		}
		return []byte(secret), nil
	}
	
	// If not found in keychain, try fallback file
	if k.fallbackPath != "" {
		data, readErr := os.ReadFile(k.fallbackPath)
		if readErr == nil {
			k.usingFallback = true
			// Try to decode base64
			decoded, decodeErr := base64.StdEncoding.DecodeString(string(data))
			if decodeErr == nil {
				return decoded, nil
			}
			return data, nil
		}
		
		// If cannot read fallback file
		if errors.Is(readErr, os.ErrNotExist) {
			return nil, ErrSecretNotFound
		}
		
		return nil, fmt.Errorf("failed to read fallback secret: %w", readErr)
	}
	
	// Return appropriate error
	if err == keyring.ErrNotFound {
		return nil, ErrSecretNotFound
	}
	
	return nil, fmt.Errorf("failed to get secret: %w", err)
}

// SaveSecret saves a secret to the keychain
func (k *KeychainIntegration) SaveSecret(secret []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	
	// Encode as base64 to ensure binary safety
	encoded := base64.StdEncoding.EncodeToString(secret)
	
	// Try to save to keychain
	err := keyring.Set(k.service, k.account, encoded)
	if err == nil {
		k.usingFallback = false
		return nil
	}
	
	// If keychain save failed, try fallback file
	if k.fallbackPath != "" {
		// Ensure directory exists
		dir := filepath.Dir(k.fallbackPath)
		if mkdirErr := os.MkdirAll(dir, 0700); mkdirErr != nil {
			return fmt.Errorf("failed to create fallback directory: %w", mkdirErr)
		}
		
		// Write secret with secure permissions
		if writeErr := os.WriteFile(k.fallbackPath, []byte(encoded), 0600); writeErr != nil {
			return fmt.Errorf("failed to write fallback secret: %w", writeErr)
		}
		
		k.usingFallback = true
		return nil
	}
	
	return fmt.Errorf("failed to save secret and no fallback available: %w", err)
}

// DeleteSecret removes a secret from the keychain
func (k *KeychainIntegration) DeleteSecret() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	
	// Try to delete from keychain first
	err := keyring.Delete(k.service, k.account)
	if err != nil && err != keyring.ErrNotFound {
		// Real error from keychain (not just "not found")
		// We'll still try to delete from fallback
	}
	
	// Always try to remove the fallback file regardless of keychain status
	if k.fallbackPath != "" {
		if removeErr := os.Remove(k.fallbackPath); removeErr != nil {
			if !os.IsNotExist(removeErr) {
				return fmt.Errorf("failed to delete fallback secret: %w", removeErr)
			}
		}
	}
	
	// If keychain delete had an error other than "not found", report it
	if err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("warning: failed to delete from keychain: %w", err)
	}
	
	k.usingFallback = false
	return nil
}

// MockInit initializes the keyring with a mock provider for testing
func MockInit() {
	keyring.MockInit()
}
