package auth

import (
	"sync"
	"time"

	"applock-go/internal/logging"
)

// BruteForceProtector implements protection against brute force attacks
type BruteForceProtector struct {
	maxAttempts        int
	lockoutDuration    time.Duration
	attemptResetWindow time.Duration
	attempts           map[string]*appAttempts
	mu                 sync.RWMutex
}

// appAttempts tracks authentication attempts for a single application
type appAttempts struct {
	remaining       int
	lastAttemptTime time.Time
	lockedOutUntil  time.Time
}

// NewBruteForceProtector creates a new brute force protector
func NewBruteForceProtector(maxAttempts int, lockoutDuration, attemptResetWindow time.Duration) *BruteForceProtector {
	return &BruteForceProtector{
		maxAttempts:        maxAttempts,
		lockoutDuration:    lockoutDuration,
		attemptResetWindow: attemptResetWindow,
		attempts:           make(map[string]*appAttempts),
	}
}

// RecordFailedAttempt records a failed authentication attempt
func (bf *BruteForceProtector) RecordFailedAttempt(appIdentifier string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	attempts := bf.getOrCreateAttemptsLocked(appIdentifier, now)

	// If already at zero, just update the lockout time
	if attempts.remaining <= 0 {
		attempts.lockedOutUntil = now.Add(bf.lockoutDuration)
		attempts.lastAttemptTime = now

		// Log the continued lockout
		if logging.SecurityLog != nil {
			logging.SecurityLog.LogEvent(logging.EventLockout,
				"Additional failed attempts during lockout period",
				map[string]interface{}{
					"app_identifier": appIdentifier,
					"locked_until":   attempts.lockedOutUntil,
				},
			)
		}
		return
	}

	// Decrement remaining attempts
	attempts.remaining--
	attempts.lastAttemptTime = now

	// If we've hit zero, initiate lockout
	if attempts.remaining <= 0 {
		attempts.lockedOutUntil = now.Add(bf.lockoutDuration)

		// Log the lockout
		if logging.SecurityLog != nil {
			logging.SecurityLog.LogBruteForceEvent(
				appIdentifier,
				attempts.remaining,
				bf.lockoutDuration,
				map[string]interface{}{
					"locked_until": attempts.lockedOutUntil,
				},
			)
		}
	} else {
		// Log the failed attempt if not locked out
		if logging.SecurityLog != nil {
			logging.SecurityLog.LogEvent(logging.EventAuthFailure,
				"Authentication attempt failed",
				map[string]interface{}{
					"app_identifier":     appIdentifier,
					"remaining_attempts": attempts.remaining,
				},
			)
		}
	}
}

// RecordSuccessfulAttempt records a successful authentication attempt
func (bf *BruteForceProtector) RecordSuccessfulAttempt(appIdentifier string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	// Reset attempts on success
	now := time.Now()
	attempts := bf.getOrCreateAttemptsLocked(appIdentifier, now)

	// Only reset if not currently locked out
	if now.After(attempts.lockedOutUntil) {
		wasLocked := attempts.remaining <= 0

		attempts.remaining = bf.maxAttempts
		attempts.lastAttemptTime = now
		attempts.lockedOutUntil = time.Time{} // Clear lockout

		// Log if coming out of a lockout
		if wasLocked && logging.SecurityLog != nil {
			logging.SecurityLog.LogEvent(logging.EventUnlockout,
				"Application unlocked after successful authentication",
				map[string]interface{}{
					"app_identifier": appIdentifier,
				},
			)
		}
	} else {
		// Log if still locked out
		if logging.SecurityLog != nil {
			logging.SecurityLog.LogEvent(logging.EventAuthSuccess,
				"Authentication succeeded but application still locked out",
				map[string]interface{}{
					"app_identifier": appIdentifier,
					"locked_until":   attempts.lockedOutUntil,
				},
			)
		}
	}
}

// IsLockedOut checks if an application is currently locked out
func (bf *BruteForceProtector) IsLockedOut(appIdentifier string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	attempts, exists := bf.attempts[appIdentifier]
	if !exists {
		return false
	}

	// Check if lockout has expired
	now := time.Now()
	return now.Before(attempts.lockedOutUntil)
}

// GetRemainingAttempts returns the number of authentication attempts remaining
func (bf *BruteForceProtector) GetRemainingAttempts(appIdentifier string) int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	now := time.Now()

	// Check if we have existing attempts data
	attempts, exists := bf.attempts[appIdentifier]
	if !exists {
		return bf.maxAttempts
	}

	// Check if attempts should be reset due to time window
	if now.Sub(attempts.lastAttemptTime) > bf.attemptResetWindow {
		// Cannot modify in a read lock, so just report max attempts
		return bf.maxAttempts
	}

	// Check if lockout has expired but attempts not reset
	if now.After(attempts.lockedOutUntil) && attempts.remaining <= 0 {
		return 0 // Still at zero attempts but not locked out
	}

	return attempts.remaining
}

// GetLockoutRemaining returns the time left in the lockout period
func (bf *BruteForceProtector) GetLockoutRemaining(appIdentifier string) time.Duration {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	attempts, exists := bf.attempts[appIdentifier]
	if !exists {
		return 0
	}

	now := time.Now()
	if now.After(attempts.lockedOutUntil) {
		return 0
	}

	return attempts.lockedOutUntil.Sub(now)
}

// Reset clears all tracking data for all applications
func (bf *BruteForceProtector) Reset() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	bf.attempts = make(map[string]*appAttempts)
}

// ResetApplication clears tracking data for a specific application
func (bf *BruteForceProtector) ResetApplication(appIdentifier string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	delete(bf.attempts, appIdentifier)
}

// getOrCreateAttemptsLocked gets or creates an attempts entry for an application
// Must be called with lock held
func (bf *BruteForceProtector) getOrCreateAttemptsLocked(appIdentifier string, now time.Time) *appAttempts {
	attempts, exists := bf.attempts[appIdentifier]

	if !exists {
		attempts = &appAttempts{
			remaining:       bf.maxAttempts,
			lastAttemptTime: now,
		}
		bf.attempts[appIdentifier] = attempts
	} else if now.Sub(attempts.lastAttemptTime) > bf.attemptResetWindow {
		// Reset attempts if outside the tracking window
		attempts.remaining = bf.maxAttempts
	}

	return attempts
}
