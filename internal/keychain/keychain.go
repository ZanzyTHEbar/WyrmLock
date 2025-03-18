package keychain

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

// KeychainIntegration handles interactions with the system keyring (cross-platform)
type KeychainIntegration struct {
	// Service and account names for the keychain items
	service string
	account string
}

// NewKeychainIntegration creates a new keychain integration
func NewKeychainIntegration(service, account string) (*KeychainIntegration, error) {
	if service == "" || account == "" {
		return nil, errors.New("service and account names cannot be empty")
	}
	
	return &KeychainIntegration{
		service: service,
		account: account,
	}, nil
}

// SecretExists checks if a secret exists in the keychain
func (k *KeychainIntegration) SecretExists() (bool, error) {
	_, err := keyring.Get(k.service, k.account)
	if err == nil {
		return true, nil
	}
	
	// Check if it's a "secret not found" error
	if err == keyring.ErrNotFound {
		return false, nil
	}
	
	// Any other error is a real error
	return false, fmt.Errorf("failed to check if secret exists: %w", err)
}

// GetSecret retrieves a secret from the keychain
func (k *KeychainIntegration) GetSecret() ([]byte, error) {
	secret, err := keyring.Get(k.service, k.account)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, errors.New("secret not found in keychain")
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	
	// Return the secret as a byte array
	return []byte(secret), nil
}

// SaveSecret saves a secret to the keychain
func (k *KeychainIntegration) SaveSecret(secret []byte) error {
	err := keyring.Set(k.service, k.account, string(secret))
	if err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}
	return nil
}

// DeleteSecret removes a secret from the keychain
func (k *KeychainIntegration) DeleteSecret() error {
	err := keyring.Delete(k.service, k.account)
	if err != nil {
		if err == keyring.ErrNotFound {
			// If the secret doesn't exist, consider the deletion successful
			return nil
		}
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

// MockInit initializes the keyring with a mock provider for testing
func MockInit() {
	keyring.MockInit()
}
