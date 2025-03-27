package testutil

import (
	"context"
	"errors"
	"sync"

	"wyrmlock/internal/privilege"
)

// MockPrivilegeManager implements privilege.PrivilegeManager interface for testing
type MockPrivilegeManager struct {
	// Behavior controls
	ShouldFailCapabilitySet     bool
	ShouldFailPrivilegeDrop     bool
	ShouldFailCapabilityVerify  bool
	ShouldFailCapabilityRestore bool
	
	// Tracking fields
	CurrentCapabilities []privilege.Capability
	IsPrivilegeDropped  bool
	Operations          []string
	VerificationCalls   int
	mu                  sync.Mutex
}

// NewMockPrivilegeManager creates a new mock privilege manager
func NewMockPrivilegeManager() *MockPrivilegeManager {
	return &MockPrivilegeManager{
		CurrentCapabilities: []privilege.Capability{},
		Operations:          make([]string, 0),
	}
}

// DropPrivileges mocks dropping privileges while retaining capabilities
func (m *MockPrivilegeManager) DropPrivileges() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "drop_privileges")
	
	if m.ShouldFailPrivilegeDrop {
		return errors.New("mock privilege drop failure")
	}
	
	m.IsPrivilegeDropped = true
	return nil
}

// VerifyCapabilities mocks verifying that all required capabilities are present
func (m *MockPrivilegeManager) VerifyCapabilities() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "verify_capabilities")
	m.VerificationCalls++
	
	if m.ShouldFailCapabilityVerify {
		return errors.New("mock capability verification failure")
	}
	
	return nil
}

// StartVerificationLoop mocks starting a verification loop
func (m *MockPrivilegeManager) StartVerificationLoop(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "start_verification_loop")
	
	// Note: In real implementation this would start a goroutine
	// For the mock, we just record that it was called
}

// SetCapabilities mocks setting required capabilities
func (m *MockPrivilegeManager) SetCapabilities(caps []privilege.Capability) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "set_capabilities")
	
	if m.ShouldFailCapabilitySet {
		return errors.New("mock capability set failure")
	}
	
	m.CurrentCapabilities = make([]privilege.Capability, len(caps))
	copy(m.CurrentCapabilities, caps)
	return nil
}

// HasCapability checks if a specific capability is set
func (m *MockPrivilegeManager) HasCapability(cap privilege.Capability) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "has_capability")
	
	for _, c := range m.CurrentCapabilities {
		if c == cap {
			return true
		}
	}
	
	return false
}

// IsRoot checks if running as root
func (m *MockPrivilegeManager) IsRoot() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "is_root")
	
	return !m.IsPrivilegeDropped
}

// RestoreCapabilities mocks restoring capabilities
func (m *MockPrivilegeManager) RestoreCapabilities(caps []privilege.Capability) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "restore_capabilities")
	
	if m.ShouldFailCapabilityRestore {
		return errors.New("mock capability restore failure")
	}
	
	m.CurrentCapabilities = make([]privilege.Capability, len(caps))
	copy(m.CurrentCapabilities, caps)
	return nil
}

// ClearCapabilities mocks clearing all capabilities
func (m *MockPrivilegeManager) ClearCapabilities() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Operations = append(m.Operations, "clear_capabilities")
	
	m.CurrentCapabilities = []privilege.Capability{}
	return nil
} 