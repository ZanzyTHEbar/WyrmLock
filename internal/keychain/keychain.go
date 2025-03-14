package keychain

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// KeychainIntegration handles interactions with the Linux keychain (gnome-keyring)
type KeychainIntegration struct {
	// Service and account names for the keychain items
	service string
	account string
}

// NewKeychainIntegration creates a new keychain integration
func NewKeychainIntegration(service, account string) (*KeychainIntegration, error) {
	// Check if gnome-keyring is available
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return nil, fmt.Errorf("secret-tool command not found; gnome-keyring might not be installed: %w", err)
	}

	return &KeychainIntegration{
		service: service,
		account: account,
	}, nil
}

// SecretExists checks if a secret exists in the keychain
func (k *KeychainIntegration) SecretExists() (bool, error) {
	// Use secret-tool to check if the secret exists
	cmd := exec.Command("secret-tool", "lookup",
		"service", k.service,
		"account", k.account)

	// We don't care about the output, just whether it exists
	err := cmd.Run()

	// Exit status 0 means the secret exists
	if err == nil {
		return true, nil
	}

	// If the command failed with a non-zero exit status, the secret doesn't exist
	if _, ok := err.(*exec.ExitError); ok {
		return false, nil
	}

	// Any other error is a real error
	return false, fmt.Errorf("failed to check if secret exists: %w", err)
}

// GetSecret retrieves a secret from the keychain
func (k *KeychainIntegration) GetSecret() ([]byte, error) {
	// Use secret-tool to get the secret
	cmd := exec.Command("secret-tool", "lookup",
		"service", k.service,
		"account", k.account)

	// Capture the output
	output, err := cmd.Output()
	if err != nil {
		// If the command failed with a non-zero exit status, the secret doesn't exist
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "No such secret") {
				return nil, errors.New("secret not found in keychain")
			}
		}

		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Return the output (the secret)
	return output, nil
}

// SaveSecret saves a secret to the keychain
func (k *KeychainIntegration) SaveSecret(secret []byte) error {
	// Use secret-tool to store the secret
	cmd := exec.Command("secret-tool", "store",
		"--label", "Applock-go Authentication Secret",
		"service", k.service,
		"account", k.account)

	// Provide the secret as input
	cmd.Stdin = strings.NewReader(string(secret))

	// Execute the command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	return nil
}

// DeleteSecret removes a secret from the keychain
func (k *KeychainIntegration) DeleteSecret() error {
	// Use secret-tool to delete the secret
	cmd := exec.Command("secret-tool", "clear",
		"service", k.service,
		"account", k.account)

	// Execute the command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}
