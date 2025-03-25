package daemon

import (
	"fmt"
	"sync"
	"time"

	"applock-go/internal/ipc"
	"applock-go/internal/logging"
	"applock-go/internal/monitor"
)

// DaemonStatus represents the current state of the daemon
type DaemonStatus struct {
	IsConnected      bool                  `json:"is_connected"`
	LastPingTime     time.Time             `json:"last_ping_time"`
	ConnectedSince   time.Time             `json:"connected_since,omitempty"`
	PingLatency      time.Duration         `json:"ping_latency_ms"`
	ActiveProcesses  []monitor.ProcessInfo `json:"active_processes,omitempty"`
	BlockedApps      int                   `json:"blocked_apps"`
	ProtectedApps    []string              `json:"protected_apps,omitempty"`
	Version          string                `json:"version"`
	SystemErrors     []string              `json:"system_errors,omitempty"`
	BruteForceEvents int                   `json:"brute_force_events"`
}

// StatusMonitor monitors and reports on daemon status
type StatusMonitor struct {
	client      *Client
	status      DaemonStatus
	statusMu    sync.RWMutex
	logger      *logging.Logger
	stopCh      chan struct{}
	listeners   []StatusListener
	listenersMu sync.RWMutex
}

// StatusListener is notified when the daemon status changes
type StatusListener func(status DaemonStatus)

// NewStatusMonitor creates a new daemon status monitor
func NewStatusMonitor(client *Client) *StatusMonitor {
	logger := logging.DefaultLogger
	if logger == nil {
		logger = logging.NewLogger("[status]", false)
	}

	return &StatusMonitor{
		client:    client,
		logger:    logger,
		stopCh:    make(chan struct{}),
		listeners: make([]StatusListener, 0),
		status: DaemonStatus{
			IsConnected:      false,
			SystemErrors:     make([]string, 0),
			Version:          "unknown",
			BruteForceEvents: 0,
		},
	}
}

// Start begins monitoring the daemon status
func (m *StatusMonitor) Start() {
	// Register security event listener if security logger is available
	if logging.SecurityLog != nil {
		logging.SecurityLog.AddEventListener(m.handleSecurityEvent)
	}

	// Start status polling in a separate goroutine
	go m.pollDaemonStatus()
}

// Stop stops monitoring daemon status
func (m *StatusMonitor) Stop() {
	close(m.stopCh)
}

// AddStatusListener registers a callback for status changes
func (m *StatusMonitor) AddStatusListener(listener StatusListener) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()
	m.listeners = append(m.listeners, listener)

	// Immediately notify with current status
	go listener(m.GetStatus())
}

// GetStatus returns the current daemon status
func (m *StatusMonitor) GetStatus() DaemonStatus {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	return m.status
}

// pollDaemonStatus continuously polls the daemon for status updates
func (m *StatusMonitor) pollDaemonStatus() {
	pingTicker := time.NewTicker(5 * time.Second)
	statsTicker := time.NewTicker(10 * time.Second)
	defer pingTicker.Stop()
	defer statsTicker.Stop()

	// Initial ping and stats
	m.updateConnectionStatus()
	m.updateStatusStats()

	for {
		select {
		case <-m.stopCh:
			return
		case <-pingTicker.C:
			m.updateConnectionStatus()
		case <-statsTicker.C:
			m.updateStatusStats()
		}
	}
}

// updateConnectionStatus checks the daemon connection
func (m *StatusMonitor) updateConnectionStatus() {
	start := time.Now()
	connected, err := m.client.Ping()
	latency := time.Since(start)

	m.statusMu.Lock()
	defer m.statusMu.Unlock()

	// Update connection status
	wasConnected := m.status.IsConnected
	m.status.IsConnected = connected && err == nil
	m.status.PingLatency = latency

	if m.status.IsConnected {
		m.status.LastPingTime = time.Now()
		if !wasConnected {
			m.status.ConnectedSince = time.Now()
			m.logger.Info("Connected to daemon")
		}
	} else if wasConnected {
		m.logger.Warn("Lost connection to daemon")
		if err != nil {
			m.addSystemError(fmt.Sprintf("Connection error: %v", err))
		}
	}

	// Notify status listeners
	m.notifyListeners()
}

// updateStatusStats polls for extended daemon status information
func (m *StatusMonitor) updateStatusStats() {
	if !m.GetStatus().IsConnected {
		return
	}

	// Request daemon status
	err := m.client.sendMessage(ipc.Message{Type: ipc.MsgStatusRequest})
	if err != nil {
		m.logger.Errorf("Failed to request daemon status: %v", err)
		return
	}

	// Status response will be handled asynchronously by the client's message handler
}

// handleStatusResponse processes a status response from the daemon
func (m *StatusMonitor) HandleStatusResponse(msg ipc.Message) {
	if msg.Type != ipc.MsgStatusResponse {
		return
	}

	m.statusMu.Lock()
	defer m.statusMu.Unlock()

	// Update status from message
	if msg.ProcessList != nil {
		m.status.ActiveProcesses = msg.ProcessList
	}

	if msg.ProtectedApps != nil {
		m.status.ProtectedApps = msg.ProtectedApps
		m.status.BlockedApps = len(msg.ProtectedApps)
	}

	if msg.Version != "" {
		m.status.Version = msg.Version
	}

	// Notify status listeners
	m.notifyListeners()
}

// handleSecurityEvent processes security events
func (m *StatusMonitor) handleSecurityEvent(event logging.SecurityEvent) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()

	// Update status based on security event
	switch event.EventType {
	case logging.EventBruteForceDetect:
		m.status.BruteForceEvents++
	case logging.EventSystemError:
		m.addSystemErrorLocked(event.Message)
	}

	// Notify status listeners
	m.notifyListeners()
}

// addSystemError adds an error to the system errors list
func (m *StatusMonitor) addSystemError(err string) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	m.addSystemErrorLocked(err)
}

// addSystemErrorLocked adds an error to the system errors list (with lock already held)
func (m *StatusMonitor) addSystemErrorLocked(err string) {
	// Keep only the last 10 errors
	if len(m.status.SystemErrors) >= 10 {
		m.status.SystemErrors = m.status.SystemErrors[1:]
	}
	m.status.SystemErrors = append(m.status.SystemErrors, err)
}

// notifyListeners notifies all status listeners of the current status
func (m *StatusMonitor) notifyListeners() {
	status := m.GetStatus()

	m.listenersMu.RLock()
	listeners := make([]StatusListener, len(m.listeners))
	copy(listeners, m.listeners)
	m.listenersMu.RUnlock()

	for _, listener := range listeners {
		go listener(status)
	}
}
