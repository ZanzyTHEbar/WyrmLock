package auth

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrMaxAttemptsExceeded = errors.New("maximum authentication attempts exceeded")
	ErrTempLockout         = errors.New("temporarily locked out")
)

// AuthAttempt tracks authentication attempts for an application
type AuthAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

// BruteForceProtection manages authentication attempts and lockouts
type BruteForceProtection struct {
	maxAttempts     int
	lockoutDuration time.Duration
	attempts        map[string]*AuthAttempt
	mu              sync.RWMutex
}

// NewBruteForceProtection creates a new brute force protection manager
func NewBruteForceProtection(maxAttempts int, lockoutDuration time.Duration) *BruteForceProtection {
	return &BruteForceProtection{
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
		attempts:        make(map[string]*AuthAttempt),
	}
}

// CheckAttempt verifies if an authentication attempt is allowed
func (b *BruteForceProtection) CheckAttempt(appPath string) error {
	b.mu.RLock()
	attempt, exists := b.attempts[appPath]
	b.mu.RUnlock()

	if !exists {
		return nil
	}

	// Check if currently locked out
	if time.Now().Before(attempt.LockedUntil) {
		return ErrTempLockout
	}

	// Check if max attempts exceeded
	if attempt.FailedAttempts >= b.maxAttempts {
		return ErrMaxAttemptsExceeded
	}

	return nil
}

// RecordFailure records a failed authentication attempt
func (b *BruteForceProtection) RecordFailure(appPath string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	attempt, exists := b.attempts[appPath]
	if !exists {
		attempt = &AuthAttempt{}
		b.attempts[appPath] = attempt
	}

	attempt.FailedAttempts++
	attempt.LastAttempt = time.Now()

	// If max attempts reached, set lockout
	if attempt.FailedAttempts >= b.maxAttempts {
		attempt.LockedUntil = time.Now().Add(b.lockoutDuration)
	}
}

// RecordSuccess resets the failed attempts counter
func (b *BruteForceProtection) RecordSuccess(appPath string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.attempts, appPath)
}

// GetRemainingAttempts returns the number of attempts remaining
func (b *BruteForceProtection) GetRemainingAttempts(appPath string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	attempt, exists := b.attempts[appPath]
	if !exists {
		return b.maxAttempts
	}

	remaining := b.maxAttempts - attempt.FailedAttempts
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetLockoutDuration returns the remaining lockout duration
func (b *BruteForceProtection) GetLockoutDuration(appPath string) time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()

	attempt, exists := b.attempts[appPath]
	if !exists {
		return 0
	}

	if time.Now().Before(attempt.LockedUntil) {
		return time.Until(attempt.LockedUntil)
	}
	return 0
}

// ResetAttempts resets the attempts counter for an application
func (b *BruteForceProtection) ResetAttempts(appPath string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.attempts, appPath)
}
