package auth

import (
	"strings"
	"testing"
)

// TestHashGeneration tests that hash generation works properly for all supported algorithms
func TestHashGeneration(t *testing.T) {
	// Test all supported hash algorithms
	algorithms := []string{"bcrypt", "argon2id", "scrypt", "pbkdf2"}
	password := []byte("test-password-123")

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			// Generate hash
			hash, err := GenerateHash(password, algorithm)
			if err != nil {
				t.Fatalf("Failed to generate %s hash: %v", algorithm, err)
			}

			// Verify hash format based on algorithm
			hashStr := string(hash)
			t.Logf("Generated %s hash: %s", algorithm, hashStr)

			switch algorithm {
			case "bcrypt":
				if !strings.HasPrefix(hashStr, "$2a$") {
					t.Errorf("Bcrypt hash has incorrect format: %s", hashStr)
				}
			case "argon2id":
				if !strings.HasPrefix(hashStr, "$argon2id$") {
					t.Errorf("Argon2id hash has incorrect format: %s", hashStr)
				}
			case "scrypt":
				if !strings.HasPrefix(hashStr, "$scrypt$") {
					t.Errorf("Scrypt hash has incorrect format: %s", hashStr)
				}
			case "pbkdf2":
				if !strings.HasPrefix(hashStr, "$pbkdf2-sha256$") {
					t.Errorf("PBKDF2 hash has incorrect format: %s", hashStr)
				}
			}

			// Verify that comparison works using the built-in Compare function
			success, err := Compare(password, hash)
			if err != nil {
				t.Errorf("Comparison for %s failed: %v", algorithm, err)
			}
			if !success {
				t.Errorf("%s hash should have matched but didn't", algorithm)
			}

			// Test with incorrect password using the Compare function
			wrongPassword := []byte("wrong-password")
			success, err = Compare(wrongPassword, hash)
			if err != nil {
				t.Errorf("Comparison with wrong password for %s failed with error: %v", algorithm, err)
			}
			if success {
				t.Errorf("%s hash should not have matched with wrong password but did", algorithm)
			}
		})
	}
}

// TestUnsupportedHashAlgorithm tests that an error is returned for unsupported algorithms
func TestUnsupportedHashAlgorithm(t *testing.T) {
	_, err := GenerateHash([]byte("password"), "unsupported")
	if err == nil {
		t.Errorf("Expected error for unsupported algorithm, got nil")
	}
	
	if !strings.Contains(err.Error(), "unsupported hash algorithm") {
		t.Errorf("Expected error message to contain 'unsupported hash algorithm', got: %v", err)
	}
} 