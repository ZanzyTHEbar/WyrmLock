package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Security event types
const (
	EventAuthAttempt       = "AUTH_ATTEMPT"
	EventAuthSuccess       = "AUTH_SUCCESS"
	EventAuthFailure       = "AUTH_FAILURE"
	EventBruteForceDetect  = "BRUTE_FORCE_DETECT"
	EventLockout           = "LOCKOUT"
	EventUnlockout         = "UNLOCKOUT"
	EventConfigChange      = "CONFIG_CHANGE"
	EventServiceStart      = "SERVICE_START"
	EventServiceStop       = "SERVICE_STOP"
	EventSystemError       = "SYSTEM_ERROR"
	EventSecurityViolation = "SECURITY_VIOLATION"
	EventProcessBlocked    = "PROCESS_BLOCKED"
	EventProcessAllowed    = "PROCESS_ALLOWED"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	ProcessPath string                 `json:"process_path,omitempty"`
	ProcessID   int                    `json:"process_id,omitempty"`
	Username    string                 `json:"username,omitempty"`
	Success     bool                   `json:"success,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// SecurityLogger handles logging of security events
type SecurityLogger struct {
	logger         *Logger
	logFile        *os.File
	logPath        string
	mu             sync.Mutex
	eventListeners []EventListener
}

// EventListener is a callback function that receives security events
type EventListener func(event SecurityEvent)

// NewSecurityLogger creates a new security logger
func NewSecurityLogger(logPath string, stdLogger *Logger) (*SecurityLogger, error) {
	if logPath == "" {
		// Default log path
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		logPath = filepath.Join(homeDir, ".wyrmlock", "security.log")
	}

	// Ensure directory exists
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file (append mode)
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open security log file: %w", err)
	}

	// Use default logger if none provided
	if stdLogger == nil {
		stdLogger = DefaultLogger
		if stdLogger == nil {
			stdLogger = NewLogger("[security]", false)
		}
	}

	return &SecurityLogger{
		logger:         stdLogger,
		logFile:        logFile,
		logPath:        logPath,
		eventListeners: make([]EventListener, 0),
	}, nil
}

// Close closes the security logger
func (sl *SecurityLogger) Close() error {
	if sl.logFile != nil {
		return sl.logFile.Close()
	}
	return nil
}

// LogEvent logs a security event
func (sl *SecurityLogger) LogEvent(eventType string, message string, details map[string]interface{}) {
	event := SecurityEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Message:   message,
		Details:   details,
	}

	sl.logEventObject(event)
}

// LogAuthAttempt logs an authentication attempt
func (sl *SecurityLogger) LogAuthAttempt(processPath string, pid int, username string, success bool, details map[string]interface{}) {
	event := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthAttempt,
		ProcessPath: processPath,
		ProcessID:   pid,
		Username:    username,
		Success:     success,
		Details:     details,
	}

	// Set message based on success
	if success {
		event.Message = "Authentication successful"
		event.EventType = EventAuthSuccess
	} else {
		event.Message = "Authentication failed"
		event.EventType = EventAuthFailure
	}

	sl.logEventObject(event)
}

// LogProcessEvent logs a process-related event
func (sl *SecurityLogger) LogProcessEvent(eventType string, processPath string, pid int, details map[string]interface{}) {
	event := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		ProcessPath: processPath,
		ProcessID:   pid,
		Details:     details,
	}

	sl.logEventObject(event)
}

// LogBruteForceEvent logs a brute force detection event
func (sl *SecurityLogger) LogBruteForceEvent(processPath string, remainingAttempts int, lockoutDuration time.Duration, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}

	details["remaining_attempts"] = remainingAttempts
	details["lockout_duration_seconds"] = lockoutDuration.Seconds()

	event := SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   EventBruteForceDetect,
		ProcessPath: processPath,
		Message:     "Potential brute force attack detected",
		Details:     details,
	}

	sl.logEventObject(event)
}

// AddEventListener registers a callback for security events
func (sl *SecurityLogger) AddEventListener(listener EventListener) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.eventListeners = append(sl.eventListeners, listener)
}

// logEventObject logs a security event and notifies listeners
func (sl *SecurityLogger) logEventObject(event SecurityEvent) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Convert event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		sl.logger.Errorf("Failed to marshal security event: %v", err)
		return
	}

	// Write to log file
	if sl.logFile != nil {
		if _, err := sl.logFile.Write(append(eventJSON, '\n')); err != nil {
			sl.logger.Errorf("Failed to write security event to file: %v", err)
		}
	}

	// Log to standard logger as well
	switch event.EventType {
	case EventAuthSuccess:
		sl.logger.Infof("Authentication successful for process %s (PID: %d)", event.ProcessPath, event.ProcessID)
	case EventAuthFailure:
		sl.logger.Warnf("Authentication failed for process %s (PID: %d)", event.ProcessPath, event.ProcessID)
	case EventBruteForceDetect:
		sl.logger.Warnf("Possible brute force attack detected for %s", event.ProcessPath)
	case EventLockout:
		sl.logger.Warnf("Account locked out for %s", event.ProcessPath)
	case EventProcessBlocked:
		sl.logger.Infof("Process blocked: %s (PID: %d)", event.ProcessPath, event.ProcessID)
	case EventProcessAllowed:
		sl.logger.Infof("Process allowed: %s (PID: %d)", event.ProcessPath, event.ProcessID)
	case EventSecurityViolation:
		sl.logger.Errorf("Security violation: %s", event.Message)
	default:
		sl.logger.Debugf("Security event %s: %s", event.EventType, event.Message)
	}

	// Notify listeners
	for _, listener := range sl.eventListeners {
		go listener(event)
	}
}

// Instance for global usage
var SecurityLog *SecurityLogger

// InitSecurityLogger initializes the global security logger
func InitSecurityLogger(logPath string, stdLogger *Logger) error {
	var err error
	SecurityLog, err = NewSecurityLogger(logPath, stdLogger)
	return err
}
