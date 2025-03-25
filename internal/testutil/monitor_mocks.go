package testutil

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"applock-go/internal/monitor"
)

// MockProcessMonitor implements monitor.ProcessMonitor interface for testing
type MockProcessMonitor struct {
	// Behavior controls
	ShouldFailVerification bool
	ShouldDetectEvents     bool
	ShouldFailSuspend      bool
	ShouldFailResume       bool
	
	// Tracking fields
	SuspendedProcesses   map[int]bool
	TerminatedProcesses  map[int]bool
	AllowedProcesses     map[int]bool
	Verifications        map[int]bool
	Events               []string
	ProcessInfo          map[int]*monitor.ProcessInfo
	EventHandlerCallback monitor.ProcessEventHandler
	
	mu sync.Mutex
}

// NewMockProcessMonitor creates a new mock process monitor
func NewMockProcessMonitor() *MockProcessMonitor {
	return &MockProcessMonitor{
		SuspendedProcesses:  make(map[int]bool),
		TerminatedProcesses: make(map[int]bool),
		AllowedProcesses:    make(map[int]bool),
		Verifications:       make(map[int]bool),
		Events:              make([]string, 0),
		ProcessInfo:         make(map[int]*monitor.ProcessInfo),
	}
}

// Start mocks starting the process monitor
func (m *MockProcessMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Events = append(m.Events, "start")
	return nil
}

// Stop mocks stopping the process monitor
func (m *MockProcessMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Events = append(m.Events, "stop")
	return nil
}

// SuspendProcess mocks suspending a process
func (m *MockProcessMonitor) SuspendProcess(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.ShouldFailSuspend {
		return errors.New("mock suspend failure")
	}
	
	m.SuspendedProcesses[pid] = true
	m.Events = append(m.Events, fmt.Sprintf("suspend:%d", pid))
	return nil
}

// ResumeProcess mocks resuming a suspended process
func (m *MockProcessMonitor) ResumeProcess(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.ShouldFailResume {
		return errors.New("mock resume failure")
	}
	
	delete(m.SuspendedProcesses, pid)
	m.Events = append(m.Events, fmt.Sprintf("resume:%d", pid))
	return nil
}

// TerminateProcess mocks terminating a process
func (m *MockProcessMonitor) TerminateProcess(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.TerminatedProcesses[pid] = true
	delete(m.SuspendedProcesses, pid)
	m.Events = append(m.Events, fmt.Sprintf("terminate:%d", pid))
	return nil
}

// AllowProcess mocks allowing a process to run
func (m *MockProcessMonitor) AllowProcess(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.AllowedProcesses[pid] = true
	delete(m.SuspendedProcesses, pid)
	m.Events = append(m.Events, fmt.Sprintf("allow:%d", pid))
	return nil
}

// VerifyProcess mocks process verification
func (m *MockProcessMonitor) VerifyProcess(pid int) (*monitor.ProcessInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Verifications[pid] = true
	m.Events = append(m.Events, fmt.Sprintf("verify:%d", pid))
	
	if m.ShouldFailVerification {
		return nil, &monitor.ProcessVerificationError{
			Reason: "mock verification failure",
			PID:    pid,
			Detail: "test error",
		}
	}
	
	// Return stored process info if available
	if info, exists := m.ProcessInfo[pid]; exists {
		return info, nil
	}
	
	// Create mock process info
	info := &monitor.ProcessInfo{
		PID:       pid,
		Command:   "/usr/bin/testapp",
		ExecHash:  "mock-hash-value",
		ParentPID: 1,
		Allowed:   m.AllowedProcesses[pid],
		StartTime: time.Now().Unix(),
		CmdLine:   "/usr/bin/testapp --test",
		State:     monitor.ProcessStateRunning,
	}
	
	if m.SuspendedProcesses[pid] {
		info.State = monitor.ProcessStateSuspended
	}
	
	if m.TerminatedProcesses[pid] {
		info.State = monitor.ProcessStateTerminated
	}
	
	return info, nil
}

// RegisterEventHandler mocks registering an event handler
func (m *MockProcessMonitor) RegisterEventHandler(handler monitor.ProcessEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.EventHandlerCallback = handler
	m.Events = append(m.Events, "register_handler")
}

// SimulateExecEvent simulates a process execution event
func (m *MockProcessMonitor) SimulateExecEvent(pid int, execPath string, displayName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.Events = append(m.Events, "exec_event:"+execPath)
	
	if m.EventHandlerCallback != nil && m.ShouldDetectEvents {
		// Call the registered handler
		m.EventHandlerCallback(pid, execPath, displayName)
	}
}

// SetProcessInfo sets mock process info for a specific PID
func (m *MockProcessMonitor) SetProcessInfo(info *monitor.ProcessInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.ProcessInfo[info.PID] = info
}

// IsSuspended checks if a process is suspended
func (m *MockProcessMonitor) IsSuspended(pid int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	return m.SuspendedProcesses[pid]
}

// IsTerminated checks if a process is terminated
func (m *MockProcessMonitor) IsTerminated(pid int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	return m.TerminatedProcesses[pid]
}

// IsAllowed checks if a process is allowed
func (m *MockProcessMonitor) IsAllowed(pid int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	return m.AllowedProcesses[pid]
} 