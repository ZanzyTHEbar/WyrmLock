package logging_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"wyrmlock/internal/logging"
)

func TestSecurityLogger(t *testing.T) {
	// Create temporary log file path
	tmpDir, err := os.MkdirTemp("", "applock-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	logPath := filepath.Join(tmpDir, "security.log")

	// Create the logger
	logger := logging.NewLogger("[test]", true)
	securityLogger, err := logging.NewSecurityLogger(logPath, logger)
	if err != nil {
		t.Fatalf("Failed to create security logger: %v", err)
	}
	defer securityLogger.Close()

	t.Run("LogEvent", func(t *testing.T) {
		// Log a basic event
		securityLogger.LogEvent(
			logging.EventServiceStart,
			"Service started",
			map[string]interface{}{"version": "1.0.0"},
		)

		// Verify log file exists
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			t.Fatal("Log file was not created")
		}
	})

	t.Run("LogAuthAttempt", func(t *testing.T) {
		// Log successful auth attempt
		securityLogger.LogAuthAttempt(
			"/usr/bin/sudo",
			1234,
			"testuser",
			true,
			map[string]interface{}{"method": "zero-knowledge"},
		)

		// Log failed auth attempt
		securityLogger.LogAuthAttempt(
			"/usr/bin/sudo",
			1234,
			"testuser",
			false,
			map[string]interface{}{"method": "zero-knowledge", "reason": "invalid-password"},
		)
	})

	t.Run("LogBruteForceEvent", func(t *testing.T) {
		securityLogger.LogBruteForceEvent(
			"/usr/bin/sudo",
			2,
			15*time.Minute,
			map[string]interface{}{"ip_address": "127.0.0.1"},
		)
	})

	t.Run("EventListener", func(t *testing.T) {
		eventReceived := make(chan logging.SecurityEvent, 1)

		// Register a listener
		securityLogger.AddEventListener(func(event logging.SecurityEvent) {
			eventReceived <- event
		})

		// Log an event
		expectedType := logging.EventConfigChange
		expectedMessage := "Configuration updated"
		securityLogger.LogEvent(expectedType, expectedMessage, nil)

		// Wait for the event to be processed
		select {
		case event := <-eventReceived:
			// Verify event properties
			if event.EventType != expectedType {
				t.Errorf("Expected event type %s, got %s", expectedType, event.EventType)
			}
			if event.Message != expectedMessage {
				t.Errorf("Expected message %s, got %s", expectedMessage, event.Message)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for event listener notification")
		}
	})
}

func TestSecurityLoggerGlobalInstance(t *testing.T) {
	// Test the global instance initialization
	tmpDir, err := os.MkdirTemp("", "applock-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	logPath := filepath.Join(tmpDir, "security.log")
	logger := logging.NewLogger("[test]", true)

	// Initialize the global instance
	if err := logging.InitSecurityLogger(logPath, logger); err != nil {
		t.Fatalf("Failed to initialize global security logger: %v", err)
	}

	// Ensure it's not nil
	if logging.SecurityLog == nil {
		t.Fatal("Global SecurityLog is nil after initialization")
	}

	// Log something to verify it works
	logging.SecurityLog.LogEvent(
		logging.EventServiceStart,
		"Global logger test",
		nil,
	)
}
