package auth_test

import (
	"os"
	"testing"

	"applock-go/internal/auth"
	"applock-go/internal/testutil"
)

// TestAuthenticateTraditional tests the traditional authentication methods
func TestAuthenticateTraditional(t *testing.T) {
	// Test vectors with passwords and application paths
	tests := []struct {
		name           string
		hashAlgorithm  string
		password       string
		userInput      string
		appPath        string
		expectSuccess  bool
		expectErrorMsg string
	}{
		{
			name:          "Bcrypt Successful Authentication",
			hashAlgorithm: "bcrypt",
			password:      "correct-password-123",
			userInput:     "correct-password-123",
			appPath:       "/usr/bin/testapp",
			expectSuccess: true,
		},
		{
			name:          "Bcrypt Failed Authentication",
			hashAlgorithm: "bcrypt",
			password:      "correct-password-123",
			userInput:     "wrong-password-456",
			appPath:       "/usr/bin/testapp",
			expectSuccess: false,
		},
		{
			name:          "Argon2id Successful Authentication",
			hashAlgorithm: "argon2id",
			password:      "correct-password-123",
			userInput:     "correct-password-123",
			appPath:       "/usr/bin/testapp",
			expectSuccess: true,
		},
		{
			name:          "Argon2id Failed Authentication",
			hashAlgorithm: "argon2id",
			password:      "correct-password-123",
			userInput:     "wrong-password-456",
			appPath:       "/usr/bin/testapp",
			expectSuccess: false,
		},
		{
			name:          "Scrypt Successful Authentication",
			hashAlgorithm: "scrypt",
			password:      "correct-password-123",
			userInput:     "correct-password-123",
			appPath:       "/usr/bin/testapp",
			expectSuccess: true,
		},
		{
			name:          "Scrypt Failed Authentication",
			hashAlgorithm: "scrypt",
			password:      "correct-password-123",
			userInput:     "wrong-password-456",
			appPath:       "/usr/bin/testapp",
			expectSuccess: false,
		},
		{
			name:          "PBKDF2 Successful Authentication",
			hashAlgorithm: "pbkdf2",
			password:      "correct-password-123",
			userInput:     "correct-password-123",
			appPath:       "/usr/bin/testapp",
			expectSuccess: true,
		},
		{
			name:          "PBKDF2 Failed Authentication",
			hashAlgorithm: "pbkdf2",
			password:      "correct-password-123",
			userInput:     "wrong-password-456",
			appPath:       "/usr/bin/testapp",
			expectSuccess: false,
		},
		{
			name:          "Empty Password",
			hashAlgorithm: "bcrypt",
			password:      "correct-password-123",
			userInput:     "",
			appPath:       "/usr/bin/testapp",
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use the helper function to set up an authenticator with the password
			authenticator, cleanup := testutil.SetupAuthenticatorWithPassword(
				t, tc.password, tc.hashAlgorithm, false)
			defer cleanup()

			// Verify that the secret file exists
			secretPath := authenticator.GetSecretPath() // You may need to add this getter method
			if _, err := os.Stat(secretPath); os.IsNotExist(err) {
				t.Fatalf("Secret file does not exist at %s", secretPath)
			}

			// Attempt authentication through the main Authenticate method
			success, err := authenticator.Authenticate([]byte(tc.userInput), tc.appPath)

			// Check results
			if tc.expectSuccess && !success {
				t.Errorf("Expected successful authentication, but got failure with error: %v", err)
			}

			if !tc.expectSuccess && success {
				t.Errorf("Expected authentication failure, but got success")
			}

			if tc.expectErrorMsg != "" && (err == nil || err.Error() != tc.expectErrorMsg) {
				t.Errorf("Expected error message '%s', got: %v", tc.expectErrorMsg, err)
			}
		})
	}
}

// TestHashAlgorithms tests the different hash algorithm implementations
func TestHashAlgorithms(t *testing.T) {
	// This test verifies that all hash implementations work correctly
	hashAlgorithms := []string{"bcrypt", "argon2id", "scrypt", "pbkdf2"}
	
	for _, algorithm := range hashAlgorithms {
		t.Run(algorithm, func(t *testing.T) {
			password := "test-password-123"
			wrongPassword := "wrong-password"
			appPath := "/usr/bin/testapp"
			
			// Use helper to set up authenticator with known password
			authenticator, cleanup := testutil.SetupAuthenticatorWithPassword(
				t, password, algorithm, false)
			defer cleanup()
			
			// Test with correct password
			success, err := authenticator.Authenticate([]byte(password), appPath)
			if err != nil {
				t.Errorf("Authentication with correct password failed: %v", err)
			}
			if !success {
				t.Errorf("Authentication with correct password returned false")
			}
			
			// Test with incorrect password
			success, err = authenticator.Authenticate([]byte(wrongPassword), appPath)
			if err != nil {
				t.Errorf("Authentication with wrong password failed: %v", err)
			}
			if success {
				t.Errorf("Authentication with wrong password returned true")
			}
		})
	}
}

// TestAuthenticationWithBruteForceProtection tests the integration of 
// authentication with brute force protection
func TestAuthenticationWithBruteForceProtection(t *testing.T) {
	password := "test-password-123"
	wrongPassword := "wrong-password"
	appPath := "/usr/bin/testapp"
	hashAlgorithm := "bcrypt"
	
	// Use helper to create authenticator
	authenticator, cleanup := testutil.SetupAuthenticatorWithPassword(
		t, password, hashAlgorithm, false)
	defer cleanup()
	
	// Test successful authentication
	success, err := authenticator.Authenticate([]byte(password), appPath)
	if !success || err != nil {
		t.Errorf("Initial authentication should succeed, got success=%v, err=%v", success, err)
	}
	
	// Test brute force protection by making multiple failed attempts
	maxAttempts := auth.DefaultMaxAuthAttempts
	for i := 0; i < maxAttempts; i++ {
		success, _ = authenticator.Authenticate([]byte(wrongPassword), appPath)
		if success {
			t.Errorf("Wrong password authentication should fail, got success=true on attempt %d", i+1)
		}
	}
	
	// The next attempt should be locked out
	success, err = authenticator.Authenticate([]byte(password), appPath)
	if success {
		t.Errorf("Authentication should be locked out after %d failed attempts", maxAttempts)
	}
	
	// Error should indicate max retries or lockout
	if err == nil {
		t.Errorf("Expected error for lockout, got nil")
	}
} 