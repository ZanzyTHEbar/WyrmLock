package util

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"wyrmlock/internal/logging"
)

// ShutdownHandler manages graceful application shutdown
type ShutdownHandler struct {
	shutdownFuncs []func() error
	timeout       time.Duration
	logger        *logging.Logger
	once          sync.Once
	shutdownChan  chan os.Signal
}

// NewShutdownHandler creates a new shutdown handler
func NewShutdownHandler(logger *logging.Logger, timeout time.Duration) *ShutdownHandler {
	if timeout == 0 {
		timeout = 5 * time.Second // Default timeout
	}

	return &ShutdownHandler{
		shutdownFuncs: make([]func() error, 0),
		timeout:       timeout,
		logger:        logger,
		shutdownChan:  make(chan os.Signal, 1),
	}
}

// RegisterShutdownFunc registers a function to be called during shutdown
func (h *ShutdownHandler) RegisterShutdownFunc(f func() error) {
	h.shutdownFuncs = append(h.shutdownFuncs, f)
}

// HandleShutdown starts handling OS signals for graceful shutdown
func (h *ShutdownHandler) HandleShutdown() {
	signal.Notify(h.shutdownChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-h.shutdownChan
		h.logger.Infof("Received signal %v, initiating graceful shutdown", sig)
		h.Shutdown()
	}()
}

// Shutdown executes all registered shutdown functions with a timeout
func (h *ShutdownHandler) Shutdown() {
	h.once.Do(func() {
		// Create context with timeout for shutdown operations
		ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
		defer cancel()

		// Create a channel to signal completion
		done := make(chan struct{})

		// Run shutdown functions in a goroutine
		go func() {
			for i := len(h.shutdownFuncs) - 1; i >= 0; i-- {
				f := h.shutdownFuncs[i]
				if err := f(); err != nil {
					h.logger.Errorf("Error during shutdown: %v", err)
				}
			}
			close(done)
		}()

		// Wait for either completion or timeout
		select {
		case <-done:
			h.logger.Info("Graceful shutdown completed")
		case <-ctx.Done():
			h.logger.Warn("Shutdown timed out, forcing exit")
		}

		// Force exit if necessary
		os.Exit(0)
	})
}

// CheckProcessesBeforeExit ensures that no suspended processes remain
// when the application exits
func CheckProcessesBeforeExit() error {
	// List all processes in /proc
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		// Skip non-numeric directories (non-PIDs)
		if !entry.IsDir() {
			continue
		}

		// Check if this is a suspended process that we might have handled
		statusPath := "/proc/" + entry.Name() + "/status"
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		// Check if process state indicates it's stopped (T)
		if string(data) != "" && contains(string(data), "State:	T") {
			// This is a stopped process, try to resume it to prevent orphaned
			// suspended processes when we exit
			// We'll ignore errors since we're just trying our best to clean up
			pid := atoi(entry.Name())
			if pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGCONT)
			}
		}
	}

	return nil
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return -1
		}
	}
	return n
}
