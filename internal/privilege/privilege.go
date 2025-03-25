package privilege

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"applock-go/internal/logging"

	"github.com/syndtr/gocapability/capability"
)

// Capability represents a Linux capability
type Capability int

const (
	// Required capabilities for applock
	CAP_NET_ADMIN  Capability = 12 // For netlink operations
	CAP_SYS_PTRACE Capability = 19 // For process monitoring
	CAP_SYS_ADMIN  Capability = 21 // For process control
	CAP_CHOWN      Capability = 0  // For socket permissions
	CAP_SETUID     Capability = 7  // For privilege dropping
	CAP_SETGID     Capability = 6  // For privilege dropping
	CAP_SETPCAP    Capability = 8  // For capability management
)

// PrivilegeManager handles privilege and capability management
type PrivilegeManager struct {
	logger *logging.Logger
	uid    int
	gid    int
	caps   capability.Capabilities
	mu     sync.RWMutex // Protect concurrent access
}

// NewPrivilegeManager creates a new privilege manager
func NewPrivilegeManager(logger *logging.Logger) (*PrivilegeManager, error) {
	// Initialize capabilities
	caps, err := capability.NewPid2(0)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize capabilities: %w", err)
	}

	return &PrivilegeManager{
		logger: logger,
		uid:    os.Getuid(),
		gid:    os.Getgid(),
		caps:   caps,
	}, nil
}

// StartVerificationLoop starts a goroutine that periodically verifies capabilities
func (p *PrivilegeManager) StartVerificationLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.mu.RLock()
				if err := p.VerifyCapabilities(); err != nil {
					p.logger.Errorf("Periodic capability verification failed: %v", err)
				}
				if err := p.logCapabilityState(); err != nil {
					p.logger.Errorf("Failed to log capability state: %v", err)
				}
				p.mu.RUnlock()
			}
		}
	}()
}

// logCapabilityState logs the current state of all capabilities
func (p *PrivilegeManager) logCapabilityState() error {
	if err := p.caps.Load(); err != nil {
		return fmt.Errorf("failed to load capabilities for logging: %w", err)
	}

	requiredCaps := []Capability{
		CAP_NET_ADMIN,
		CAP_SYS_PTRACE,
		CAP_SYS_ADMIN,
		CAP_CHOWN,
		CAP_SETUID,
		CAP_SETGID,
		CAP_SETPCAP,
	}

	for _, cap := range requiredCaps {
		capValue := capability.Cap(cap)
		p.logger.Debugf("Capability %v state: permitted=%v, effective=%v",
			cap,
			p.caps.Get(capability.PERMITTED, capValue),
			p.caps.Get(capability.EFFECTIVE, capValue))
	}
	return nil
}

// setCapabilities sets the process capabilities
func (p *PrivilegeManager) setCapabilities(caps []Capability) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Get current process capabilities
	if err := p.caps.Load(); err != nil {
		return fmt.Errorf("failed to load current capabilities: %w", err)
	}

	// Clear all capabilities first
	p.caps.Clear(capability.CAPS | capability.BOUNDS)

	// Set each required capability
	for _, cap := range caps {
		// Convert our Capability type to libcap type
		capValue := capability.Cap(cap)

		// Set capability in both permitted and effective sets
		p.caps.Set(capability.PERMITTED, capValue)
		p.caps.Set(capability.EFFECTIVE, capValue)

		p.logger.Debugf("Set capability: %v", cap)
	}

	// Apply the capability changes
	if err := p.caps.Apply(capability.CAPS | capability.BOUNDS); err != nil {
		return fmt.Errorf("failed to apply capabilities: %w", err)
	}

	// Log the new capability state
	if err := p.logCapabilityState(); err != nil {
		p.logger.Warnf("Failed to log capability state after setting: %v", err)
	}

	return nil
}

// VerifyCapabilities checks if all required capabilities are present
func (p *PrivilegeManager) VerifyCapabilities() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Reload current capabilities
	if err := p.caps.Load(); err != nil {
		return fmt.Errorf("failed to load capabilities for verification: %w", err)
	}

	// Required capabilities for operation
	requiredCaps := []Capability{
		CAP_NET_ADMIN,
		CAP_SYS_PTRACE,
		CAP_SYS_ADMIN,
		CAP_CHOWN,
		CAP_SETUID,
		CAP_SETGID,
		CAP_SETPCAP,
	}

	// Check each required capability
	for _, cap := range requiredCaps {
		capValue := capability.Cap(cap)

		// Check both permitted and effective sets
		if !p.caps.Get(capability.PERMITTED, capValue) {
			return fmt.Errorf("missing required permitted capability: %v", cap)
		}
		if !p.caps.Get(capability.EFFECTIVE, capValue) {
			return fmt.Errorf("missing required effective capability: %v", cap)
		}
	}

	p.logger.Debug("All required capabilities verified")
	return nil
}

// DropPrivileges drops root privileges while maintaining required capabilities
func (p *PrivilegeManager) DropPrivileges() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Set required capabilities before dropping privileges
	requiredCaps := []Capability{
		CAP_NET_ADMIN,
		CAP_SYS_PTRACE,
		CAP_SYS_ADMIN,
		CAP_CHOWN,
		CAP_SETUID,
		CAP_SETGID,
		CAP_SETPCAP,
	}

	// Log initial state
	p.logger.Debug("Current capability state before privilege drop:")
	if err := p.logCapabilityState(); err != nil {
		p.logger.Warnf("Failed to log initial capability state: %v", err)
	}

	// Set capabilities before dropping privileges
	if err := p.setCapabilities(requiredCaps); err != nil {
		return fmt.Errorf("failed to set required capabilities: %w", err)
	}

	// Verify capabilities were set correctly
	if err := p.VerifyCapabilities(); err != nil {
		return fmt.Errorf("capability verification failed: %w", err)
	}

	// Drop root privileges
	if err := p.dropRootPrivileges(); err != nil {
		return fmt.Errorf("failed to drop root privileges: %w", err)
	}

	// Verify capabilities are still present after privilege drop
	if err := p.VerifyCapabilities(); err != nil {
		return fmt.Errorf("lost required capabilities after privilege drop: %w", err)
	}

	// Log final state
	p.logger.Debug("Current capability state after privilege drop:")
	if err := p.logCapabilityState(); err != nil {
		p.logger.Warnf("Failed to log final capability state: %v", err)
	}

	p.logger.Info("Successfully dropped root privileges while maintaining required capabilities")
	return nil
}

// dropRootPrivileges drops root privileges while maintaining capabilities
func (p *PrivilegeManager) dropRootPrivileges() error {
	// Set real and effective GID first
	if err := syscall.Setregid(p.gid, p.gid); err != nil {
		return fmt.Errorf("failed to set real GID: %w", err)
	}

	// Set real and effective UID
	if err := syscall.Setreuid(p.uid, p.uid); err != nil {
		return fmt.Errorf("failed to set real UID: %w", err)
	}

	// Double-check privilege drop
	if os.Geteuid() == 0 {
		return fmt.Errorf("failed to drop root privileges")
	}

	// Verify we can't restore privileges
	if err := syscall.Setreuid(0, 0); err == nil {
		return fmt.Errorf("privileges can still be restored after drop")
	}

	return nil
}

// RestorePrivileges restores root privileges (for shutdown)
func (p *PrivilegeManager) RestorePrivileges() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Log initial state
	p.logger.Debug("Current capability state before privilege restoration:")
	if err := p.logCapabilityState(); err != nil {
		p.logger.Warnf("Failed to log initial capability state: %v", err)
	}

	// Verify we have the required capabilities
	if err := p.VerifyCapabilities(); err != nil {
		return fmt.Errorf("missing required capabilities to restore privileges: %w", err)
	}

	// Restore root UID and GID
	if err := syscall.Setreuid(0, 0); err != nil {
		return fmt.Errorf("failed to restore root UID: %w", err)
	}
	if err := syscall.Setregid(0, 0); err != nil {
		return fmt.Errorf("failed to restore root GID: %w", err)
	}

	// Verify privilege restoration
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("failed to restore root privileges")
	}

	// Log final state
	p.logger.Debug("Current capability state after privilege restoration:")
	if err := p.logCapabilityState(); err != nil {
		p.logger.Warnf("Failed to log final capability state: %v", err)
	}

	p.logger.Info("Successfully restored root privileges")
	return nil
}

// ClearCapabilities removes all capabilities
func (p *PrivilegeManager) ClearCapabilities() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Log initial state
	p.logger.Debug("Current capability state before clearing:")
	if err := p.logCapabilityState(); err != nil {
		p.logger.Warnf("Failed to log initial capability state: %v", err)
	}

	if err := p.caps.Load(); err != nil {
		return fmt.Errorf("failed to load capabilities for clearing: %w", err)
	}

	p.caps.Clear(capability.CAPS | capability.BOUNDS)

	if err := p.caps.Apply(capability.CAPS | capability.BOUNDS); err != nil {
		return fmt.Errorf("failed to clear capabilities: %w", err)
	}

	p.logger.Debug("All capabilities cleared")
	return nil
}
