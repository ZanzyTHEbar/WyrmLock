package testutil

import (
	"errors"
	"sync"
	"time"

	"wyrmlock/internal/auth"
)

// MockAuthenticator implements auth.Authenticator interface for testing
type MockAuthenticator struct {
	// Authentication behavior controls
	ShouldSucceed      bool
	ShouldTimeout      bool
	ShouldLockout      bool
	ShouldError        bool
	ErrorToReturn      error
	ZKPProtocolMessage []byte
	Iterations         int
	
	// Tracking fields
	AuthAttempts map[string]int
	LastInput    []byte
	LastAppPath  string
	Called       bool
	mu           sync.Mutex
}

// NewMockAuthenticator creates a new mock authenticator
func NewMockAuthenticator() *MockAuthenticator {
	return &MockAuthenticator{
		ShouldSucceed: true,
		AuthAttempts:  make(map[string]int),
	}
}

// AuthenticateZKP mocks the ZKP authentication process
func (m *MockAuthenticator) AuthenticateZKP(userInput []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Called = true
	m.LastInput = make([]byte, len(userInput))
	copy(m.LastInput, userInput)
	
	if m.ShouldTimeout {
		return false, auth.ErrTimeout
	}
	
	if m.ShouldError {
		if m.ErrorToReturn != nil {
			return false, m.ErrorToReturn
		}
		return false, errors.New("mock authentication error")
	}
	
	if len(userInput) == 0 {
		return false, errors.New("empty authentication input")
	}
	
	return m.ShouldSucceed, nil
}

// AuthenticateTraditional mocks traditional password authentication
func (m *MockAuthenticator) AuthenticateTraditional(userInput []byte, appPath string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Called = true
	m.LastInput = make([]byte, len(userInput))
	m.LastAppPath = appPath
	copy(m.LastInput, userInput)
	
	if m.ShouldTimeout {
		return false, auth.ErrTimeout
	}
	
	if m.ShouldError {
		if m.ErrorToReturn != nil {
			return false, m.ErrorToReturn
		}
		return false, errors.New("mock authentication error")
	}
	
	m.AuthAttempts[appPath]++
	
	if m.ShouldLockout {
		return false, auth.ErrMaxRetries
	}
	
	return m.ShouldSucceed, nil
}

// MockBruteForceProtection implements auth.BruteForceProtection interface for testing
type MockBruteForceProtection struct {
	// Behavior controls
	MaxAttempts     int
	LockoutDuration time.Duration
	ResetDuration   time.Duration
	
	// State tracking
	Attempts       map[string]int
	Lockouts       map[string]time.Time
	LastReset      map[string]time.Time
	RecordedEvents []string
	mu             sync.Mutex
}

// NewMockBruteForceProtection creates a new mock brute force protector
func NewMockBruteForceProtection() *MockBruteForceProtection {
	return &MockBruteForceProtection{
		MaxAttempts:     3,
		LockoutDuration: 5 * time.Minute,
		ResetDuration:   60 * time.Minute,
		Attempts:        make(map[string]int),
		Lockouts:        make(map[string]time.Time),
		LastReset:       make(map[string]time.Time),
		RecordedEvents:  make([]string, 0),
	}
}

// RecordFailedAttempt records a failed authentication attempt
func (m *MockBruteForceProtection) RecordFailedAttempt(appPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Attempts[appPath]++
	m.RecordedEvents = append(m.RecordedEvents, "failed:"+appPath)
	
	if m.Attempts[appPath] >= m.MaxAttempts {
		m.Lockouts[appPath] = time.Now().Add(m.LockoutDuration)
	}
}

// RecordSuccessfulAttempt records a successful authentication attempt
func (m *MockBruteForceProtection) RecordSuccessfulAttempt(appPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Attempts[appPath] = 0
	m.RecordedEvents = append(m.RecordedEvents, "success:"+appPath)
	delete(m.Lockouts, appPath)
}

// IsLockedOut checks if an application is currently locked out
func (m *MockBruteForceProtection) IsLockedOut(appPath string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	lockoutUntil, exists := m.Lockouts[appPath]
	if !exists {
		return false
	}
	
	// Check if lockout has expired
	if time.Now().After(lockoutUntil) {
		delete(m.Lockouts, appPath)
		return false
	}
	
	return true
}

// GetRemainingAttempts returns the number of remaining authentication attempts
func (m *MockBruteForceProtection) GetRemainingAttempts(appPath string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	attempts := m.Attempts[appPath]
	remaining := m.MaxAttempts - attempts
	
	if remaining < 0 {
		remaining = 0
	}
	
	return remaining
}

// GetLockoutDuration returns the remaining lockout time
func (m *MockBruteForceProtection) GetLockoutDuration(appPath string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	lockoutUntil, exists := m.Lockouts[appPath]
	if !exists {
		return 0
	}
	
	remaining := time.Until(lockoutUntil)
	if remaining < 0 {
		return 0
	}
	
	return remaining
} 