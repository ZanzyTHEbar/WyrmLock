package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"wyrmlock/internal/auth"
	"wyrmlock/internal/config"
	"wyrmlock/internal/logging"
)

// CreateTempFile creates a temporary file with specific content for testing
// Returns the file path and a cleanup function
func CreateTempFile(t *testing.T, content []byte) (string, func()) {
	tmpFile, err := os.CreateTemp("", "wyrmmlock-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}
	
	return tmpFile.Name(), func() { os.Remove(tmpFile.Name()) }
}

// CreateTempDir creates a temporary directory for testing
// Returns the directory path and a cleanup function
func CreateTempDir(t *testing.T) (string, func()) {
	tmpDir, err := os.MkdirTemp("", "wyrmmlock-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	
	return tmpDir, func() { os.RemoveAll(tmpDir) }
}

// SetupTestConfig creates a test configuration with customizable options
func SetupTestConfig(t *testing.T) *config.Config {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			UseZeroKnowledgeProof: true,
			SecretPath:            "", // Will be set by test
			GuiType:               "gtk",
			HashAlgorithm:         "bcrypt",
		},
		Monitor: config.MonitorConfig{
			ProtectedApps: []string{"/usr/bin/testapp"},
		},
		Verbose: true,
	}
	
	return cfg
}

// SetupAuthenticatorWithPassword creates an authenticator for testing with a known password
// It sets up the necessary configuration and returns the authenticator along with cleanup function
func SetupAuthenticatorWithPassword(t *testing.T, password string, hashAlgorithm string, useZKP bool) (*auth.Authenticator, func()) {
	// Create appropriate content based on authentication mode
	var content []byte
	var err error
	
	if useZKP {
		// For ZKP, use raw password
		content = []byte(password)
	} else {
		// For traditional auth, hash the password
		content, err = auth.GenerateHash([]byte(password), hashAlgorithm)
		if err != nil {
			t.Fatalf("Failed to generate password hash: %v", err)
		}
		
		t.Logf("Generated hash for testing (%s): %s", hashAlgorithm, string(content))
	}
	
	// Create temporary file with the content
	secretPath, fileCleanup := CreateTempFile(t, content)
	t.Logf("Created secret file at: %s with %d bytes", secretPath, len(content))
	
	// Create config for the authenticator
	cfg := SetupTestConfig(t)
	cfg.Auth.UseZeroKnowledgeProof = useZKP
	cfg.Auth.HashAlgorithm = hashAlgorithm
	cfg.Auth.SecretPath = secretPath
	
	// Create authenticator
	authenticator, err := auth.NewAuthenticator(cfg)
	if err != nil {
		fileCleanup()
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	
	return authenticator, fileCleanup
}

// SetupTestLogger creates a logger for testing
func SetupTestLogger() *logging.Logger {
	return logging.NewLogger("[test]", true)
}

// VerifyNoFileLeaks checks if all temporary files were properly cleaned up
func VerifyNoFileLeaks(t *testing.T, testDir string, initialFiles []string) {
	files, err := filepath.Glob(filepath.Join(testDir, "*"))
	if err != nil {
		t.Fatalf("Failed to check for file leaks: %v", err)
	}
	
	// Check if any new files exist
	if len(files) > len(initialFiles) {
		t.Errorf("Detected file leaks: %v", files)
	}
}

// CompareByteSlices compares two byte slices and returns true if they are equal
func CompareByteSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	
	return true
}

// VerifyMemoryCleared checks if a byte slice has been zeroed out
func VerifyMemoryCleared(t *testing.T, data []byte) {
	for i, b := range data {
		if b != 0 {
			t.Errorf("Memory not properly cleared at index %d: %d", i, b)
			return
		}
	}
} 