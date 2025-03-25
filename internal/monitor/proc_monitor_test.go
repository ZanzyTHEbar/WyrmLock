package monitor_test

import (
	"errors"
	"testing"

	"applock-go/internal/monitor"
)

// TestProcessVerificationError tests the process verification error handling
func TestProcessVerificationError(t *testing.T) {
	// Create a verification error
	err := &monitor.ProcessVerificationError{
		Reason: "test reason",
		PID:    12345,
		Detail: "test detail",
	}

	// Check the error message
	expected := "process verification failed for PID 12345: test reason (test detail)"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
	
	// Test error unwrapping
	var verificationErr *monitor.ProcessVerificationError
	if !errors.As(err, &verificationErr) {
		t.Errorf("Error should be unwrappable to ProcessVerificationError")
	}
}

// TestProcessInfoStates tests the process state constants
func TestProcessInfoStates(t *testing.T) {
	// Ensure states are distinct
	states := []string{
		monitor.ProcessStateRunning,
		monitor.ProcessStateSuspended,
		monitor.ProcessStateTerminated,
	}
	
	// Check that states are not empty
	for i, state := range states {
		if state == "" {
			t.Errorf("State at index %d is empty", i)
		}
	}
	
	// Check that states are unique
	for i := 0; i < len(states); i++ {
		for j := i + 1; j < len(states); j++ {
			if states[i] == states[j] {
				t.Errorf("States at indices %d and %d are the same: %s", i, j, states[i])
			}
		}
	}
}

// TestProcessInfo tests the process info struct
func TestProcessInfo(t *testing.T) {
	// Create a test process info
	info := &monitor.ProcessInfo{
		PID:       1234,
		Command:   "/usr/bin/testapp",
		ExecHash:  "test-hash",
		ParentPID: 1,
		Allowed:   true,
		StartTime: 123456789,
		CmdLine:   "/usr/bin/testapp --arg1 --arg2",
		State:     monitor.ProcessStateRunning,
	}
	
	// Check values
	if info.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", info.PID)
	}
	
	if info.Command != "/usr/bin/testapp" {
		t.Errorf("Expected command /usr/bin/testapp, got %s", info.Command)
	}
	
	if info.ExecHash != "test-hash" {
		t.Errorf("Expected hash test-hash, got %s", info.ExecHash)
	}
	
	if info.ParentPID != 1 {
		t.Errorf("Expected parent PID 1, got %d", info.ParentPID)
	}
	
	if !info.Allowed {
		t.Errorf("Expected allowed to be true")
	}
	
	if info.StartTime != 123456789 {
		t.Errorf("Expected start time 123456789, got %d", info.StartTime)
	}
	
	if info.CmdLine != "/usr/bin/testapp --arg1 --arg2" {
		t.Errorf("Expected command line '/usr/bin/testapp --arg1 --arg2', got %s", info.CmdLine)
	}
	
	if info.State != monitor.ProcessStateRunning {
		t.Errorf("Expected state %s, got %s", monitor.ProcessStateRunning, info.State)
	}
} 