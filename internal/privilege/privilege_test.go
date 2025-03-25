package privilege_test

import (
	"context"
	"testing"
	"time"

	"applock-go/internal/privilege"
	"applock-go/internal/testutil"
)

// TestCapabilityConstants tests the capability constants
func TestCapabilityConstants(t *testing.T) {
	// Ensure capabilities are appropriately defined
	caps := map[privilege.Capability]string{
		privilege.CAP_NET_ADMIN:  "NET_ADMIN",
		privilege.CAP_SYS_PTRACE: "SYS_PTRACE",
		privilege.CAP_SYS_ADMIN:  "SYS_ADMIN",
		privilege.CAP_CHOWN:      "CHOWN",
		privilege.CAP_SETUID:     "SETUID",
		privilege.CAP_SETGID:     "SETGID",
		privilege.CAP_SETPCAP:    "SETPCAP",
	}
	
	// Check that all capabilities have valid values
	for cap, name := range caps {
		if cap < 0 {
			t.Errorf("Capability %s has invalid value: %d", name, cap)
		}
	}
	
	// Check that NET_ADMIN and SYS_PTRACE are different capabilities
	if privilege.CAP_NET_ADMIN == privilege.CAP_SYS_PTRACE {
		t.Errorf("NET_ADMIN and SYS_PTRACE should be different capability values")
	}
}

// TestNewPrivilegeManager tests creating a new privilege manager
func TestNewPrivilegeManager(t *testing.T) {
	// Create a test logger
	logger := testutil.SetupTestLogger()
	
	// Create a privilege manager
	manager, err := privilege.NewPrivilegeManager(logger)
	if err != nil {
		// Skip test on permission issues
		if isPermissionError(err) {
			t.Skip("Skipping test due to permission issues")
		}
		t.Fatalf("Failed to create privilege manager: %v", err)
	}
	
	// Check the manager is not nil
	if manager == nil {
		t.Fatal("Privilege manager is nil")
	}
}

// TestStartVerificationLoop tests starting the verification loop
func TestStartVerificationLoop(t *testing.T) {
	// Create a test logger
	logger := testutil.SetupTestLogger()
	
	// Create a privilege manager
	manager, err := privilege.NewPrivilegeManager(logger)
	if err != nil {
		// Skip test on permission issues
		if isPermissionError(err) {
			t.Skip("Skipping test due to permission issues")
		}
		t.Fatalf("Failed to create privilege manager: %v", err)
	}
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	// Start verification loop
	manager.StartVerificationLoop(ctx)
	
	// Wait for context to time out
	<-ctx.Done()
	
	// This test only verifies that StartVerificationLoop doesn't panic
	// We can't easily verify the loop's functionality directly
}

// TestVerifyCapabilities tests the capability verification
func TestVerifyCapabilities(t *testing.T) {
	// Create a test logger
	logger := testutil.SetupTestLogger()
	
	// Create a privilege manager
	manager, err := privilege.NewPrivilegeManager(logger)
	if err != nil {
		// Skip test on permission issues
		if isPermissionError(err) {
			t.Skip("Skipping test due to permission issues")
		}
		t.Fatalf("Failed to create privilege manager: %v", err)
	}
	
	// Verify capabilities
	err = manager.VerifyCapabilities()
	
	// We can't make assumptions about what capabilities the test is run with
	// So we just verify the function executes
	t.Logf("VerifyCapabilities result: %v", err)
}

// Helper function to check if an error is a permission error
func isPermissionError(err error) bool {
	return err != nil && (err.Error() == "operation not permitted" || 
		err.Error() == "permission denied")
} 