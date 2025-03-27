package auth_test

import (
	"testing"
	"time"

	"wyrmlock/internal/auth"
)

func TestBruteForceProtection(t *testing.T) {
	// Create a new BruteForceProtector with a short lockout for testing
	protector := auth.NewBruteForceProtector(3, 2*time.Second, 10*time.Second)

	// Test application identifiers
	app1 := "/usr/bin/firefox"
	app2 := "/usr/bin/chromium"

	t.Run("InitialAttempts", func(t *testing.T) {
		// Initially, all apps should have maximum attempts
		if remaining := protector.GetRemainingAttempts(app1); remaining != 3 {
			t.Errorf("Expected 3 initial attempts, got %d", remaining)
		}

		if remaining := protector.GetRemainingAttempts(app2); remaining != 3 {
			t.Errorf("Expected 3 initial attempts, got %d", remaining)
		}
	})

	t.Run("FailedAttempts", func(t *testing.T) {
		// Record several failed attempts for app1
		protector.RecordFailedAttempt(app1)
		if remaining := protector.GetRemainingAttempts(app1); remaining != 2 {
			t.Errorf("Expected 2 remaining attempts, got %d", remaining)
		}

		protector.RecordFailedAttempt(app1)
		if remaining := protector.GetRemainingAttempts(app1); remaining != 1 {
			t.Errorf("Expected 1 remaining attempt, got %d", remaining)
		}

		// App2 should still have full attempts
		if remaining := protector.GetRemainingAttempts(app2); remaining != 3 {
			t.Errorf("Expected app2 to have 3 attempts, got %d", remaining)
		}
	})

	t.Run("Lockout", func(t *testing.T) {
		// One more failed attempt should trigger lockout
		protector.RecordFailedAttempt(app1)
		if remaining := protector.GetRemainingAttempts(app1); remaining != 0 {
			t.Errorf("Expected 0 remaining attempts, got %d", remaining)
		}

		// Should be locked out
		if !protector.IsLockedOut(app1) {
			t.Error("Expected app to be locked out but it wasn't")
		}

		// App2 should still be fine
		if protector.IsLockedOut(app2) {
			t.Error("Expected app2 to not be locked out but it was")
		}
	})

	t.Run("LockoutExpiry", func(t *testing.T) {
		// Wait for lockout to expire
		time.Sleep(3 * time.Second)

		// Should no longer be locked out
		if protector.IsLockedOut(app1) {
			t.Error("Expected app to no longer be locked out after expiry")
		}

		// But should still have 0 attempts remaining from previous failures
		if remaining := protector.GetRemainingAttempts(app1); remaining != 0 {
			t.Errorf("Expected 0 remaining attempts after lockout, got %d", remaining)
		}
	})

	t.Run("AttemptReset", func(t *testing.T) {
		// Wait for attempt tracking to reset
		time.Sleep(11 * time.Second)

		// Attempts should be reset to max
		if remaining := protector.GetRemainingAttempts(app1); remaining != 3 {
			t.Errorf("Expected attempts to reset to 3, got %d", remaining)
		}
	})

	t.Run("SuccessfulAuthentication", func(t *testing.T) {
		// Record a failed attempt
		protector.RecordFailedAttempt(app2)
		if remaining := protector.GetRemainingAttempts(app2); remaining != 2 {
			t.Errorf("Expected 2 remaining attempts, got %d", remaining)
		}

		// Record a successful attempt - should reset attempts
		protector.RecordSuccessfulAttempt(app2)
		if remaining := protector.GetRemainingAttempts(app2); remaining != 3 {
			t.Errorf("Expected attempts to reset to 3 after success, got %d", remaining)
		}
	})

	t.Run("MultipleApplications", func(t *testing.T) {
		apps := []string{
			"/usr/bin/app1",
			"/usr/bin/app2",
			"/usr/bin/app3",
			"/usr/bin/app4",
		}

		// Record varying numbers of failed attempts
		for i, app := range apps {
			for j := 0; j < i; j++ {
				protector.RecordFailedAttempt(app)
			}

			expectedRemaining := 3 - i
			if expectedRemaining < 0 {
				expectedRemaining = 0
			}

			if remaining := protector.GetRemainingAttempts(app); remaining != expectedRemaining {
				t.Errorf("For app%d expected %d attempts, got %d", i+1, expectedRemaining, remaining)
			}
		}
	})

	t.Run("Concurrency", func(t *testing.T) {
		// Create a new protector for this test
		p := auth.NewBruteForceProtector(5, 1*time.Second, 5*time.Second)
		app := "/usr/bin/concurrent-test"

		// Run multiple goroutines that record attempts
		done := make(chan struct{})
		for i := 0; i < 10; i++ {
			go func() {
				p.RecordFailedAttempt(app)
				done <- struct{}{}
			}()
		}

		// Wait for all goroutines to finish
		for i := 0; i < 10; i++ {
			<-done
		}

		// Should have 0 attempts remaining and be locked out
		if remaining := p.GetRemainingAttempts(app); remaining != 0 {
			t.Errorf("Expected 0 remaining attempts after concurrent failures, got %d", remaining)
		}

		if !p.IsLockedOut(app) {
			t.Error("Expected app to be locked out after concurrent failures")
		}
	})
}
