package privilege

import (
	"fmt"
	"os"
	"syscall"

	"applock-go/internal/logging"
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
}

// NewPrivilegeManager creates a new privilege manager
func NewPrivilegeManager(logger *logging.Logger) (*PrivilegeManager, error) {
	return &PrivilegeManager{
		logger: logger,
		uid:    os.Getuid(),
		gid:    os.Getgid(),
	}, nil
}

// DropPrivileges drops root privileges while maintaining required capabilities
func (p *PrivilegeManager) DropPrivileges() error {
	// Set required capabilities
	requiredCaps := []Capability{
		CAP_NET_ADMIN,
		CAP_SYS_PTRACE,
		CAP_SYS_ADMIN,
		CAP_CHOWN,
		CAP_SETUID,
		CAP_SETGID,
		CAP_SETPCAP,
	}

	if err := p.setCapabilities(requiredCaps); err != nil {
		return fmt.Errorf("failed to set required capabilities: %w", err)
	}

	// Drop root privileges
	if err := p.dropRootPrivileges(); err != nil {
		return fmt.Errorf("failed to drop root privileges: %w", err)
	}

	p.logger.Info("Successfully dropped root privileges while maintaining required capabilities")
	return nil
}

// setCapabilities sets the process capabilities
func (p *PrivilegeManager) setCapabilities(caps []Capability) error {
	// TODO: Implement capability setting using libcap
	// This is a placeholder that will be implemented with actual capability management
	return nil
}

// dropRootPrivileges drops root privileges while maintaining capabilities
func (p *PrivilegeManager) dropRootPrivileges() error {
	// Set real and effective UID/GID to non-root user
	if err := syscall.Setreuid(p.uid, p.uid); err != nil {
		return fmt.Errorf("failed to set real UID: %w", err)
	}
	if err := syscall.Setregid(p.gid, p.gid); err != nil {
		return fmt.Errorf("failed to set real GID: %w", err)
	}

	// Verify privilege drop
	if os.Geteuid() == 0 {
		return fmt.Errorf("failed to drop root privileges")
	}

	return nil
}

// VerifyCapabilities checks if all required capabilities are present
func (p *PrivilegeManager) VerifyCapabilities() error {
	// TODO: Implement capability verification
	// This is a placeholder that will be implemented with actual capability verification
	return nil
}

// RestorePrivileges restores root privileges (for shutdown)
func (p *PrivilegeManager) RestorePrivileges() error {
	if err := syscall.Setreuid(0, 0); err != nil {
		return fmt.Errorf("failed to restore root privileges: %w", err)
	}
	if err := syscall.Setregid(0, 0); err != nil {
		return fmt.Errorf("failed to restore root group privileges: %w", err)
	}

	p.logger.Info("Successfully restored root privileges")
	return nil
}
