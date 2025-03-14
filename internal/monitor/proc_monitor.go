package monitor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"applock-go/internal/auth"
	"applock-go/internal/config"
	"applock-go/internal/gui"
	"applock-go/internal/logging"
)

const (
	// Netlink constants
	NETLINK_CONNECTOR = 11
	CN_IDX_PROC       = 1
	CN_VAL_PROC       = 1

	// Proc connector operation
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE = 2

	// Proc connector events
	PROC_EVENT_NONE = 0
	PROC_EVENT_FORK = 1
	PROC_EVENT_EXEC = 2
	PROC_EVENT_UID  = 4
	PROC_EVENT_GID  = 8
	PROC_EVENT_EXIT = 0x80000000
)

// ProcessMonitor monitors process execution
type ProcessMonitor struct {
	config        *config.Config
	authenticator *auth.Authenticator
	guiManager    *gui.Manager

	sock    int
	running bool
	mu      sync.Mutex
	wg      sync.WaitGroup
	stopCh  chan struct{}

	// Map of PIDs that are being handled
	handledPids map[int]string
	handledMu   sync.Mutex

	// Logging
	logger *logging.Logger
}

// Netlink message header
type nlMsgHdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

// Connector message header
type cnMsgHdr struct {
	Id    [2]uint32
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

// Process event header
type procEventHdr struct {
	What      uint32
	CPU       uint32
	Timestamp uint64
}

// Exec event structure
type execProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor(cfg *config.Config, authenticator *auth.Authenticator) (*ProcessMonitor, error) {
	// Create GUI manager
	guiManager, err := gui.NewManager(cfg.Auth.GuiType)
	if err != nil {
		return nil, fmt.Errorf("failed to create GUI manager: %w", err)
	}

	// Get logger
	logger := logging.DefaultLogger
	if logger == nil {
		// If the default logger isn't initialized, create a new one
		logger = logging.NewLogger("[applock]", cfg.Verbose)
	}

	return &ProcessMonitor{
		config:        cfg,
		authenticator: authenticator,
		guiManager:    guiManager,
		handledPids:   make(map[int]string),
		stopCh:        make(chan struct{}),
		logger:        logger,
	}, nil
}

// Start begins monitoring process execution
func (m *ProcessMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return errors.New("process monitor already running")
	}

	m.logger.Info("Starting process monitor")

	// Open netlink socket
	sock, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM,
		NETLINK_CONNECTOR,
	)
	if err != nil {
		return fmt.Errorf("failed to create netlink socket: %w", err)
	}
	m.sock = sock

	// Bind to the socket
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
		Groups: CN_IDX_PROC,
	}
	if err := syscall.Bind(sock, addr); err != nil {
		syscall.Close(sock)
		return fmt.Errorf("failed to bind to netlink socket: %w", err)
	}

	// Subscribe to proc connector
	if err := m.subscribe(); err != nil {
		syscall.Close(sock)
		return fmt.Errorf("failed to subscribe to proc connector: %w", err)
	}

	m.running = true
	m.logger.Debug("Process monitor initialized successfully")

	// Start monitoring in a separate goroutine
	m.wg.Add(1)
	go m.monitor()

	return nil
}

// subscribe sends a message to the kernel to subscribe to process events
func (m *ProcessMonitor) subscribe() error {
	// Create netlink header
	nlh := nlMsgHdr{
		Len: uint32(unsafe.Sizeof(nlMsgHdr{})) +
			uint32(unsafe.Sizeof(cnMsgHdr{})) +
			uint32(unsafe.Sizeof(uint32(0))),
		Type:  syscall.NLMSG_DONE,
		Flags: 0,
		Seq:   0,
		Pid:   uint32(os.Getpid()),
	}

	// Create connector header
	cnh := cnMsgHdr{
		Id:    [2]uint32{CN_IDX_PROC, CN_VAL_PROC},
		Seq:   0,
		Ack:   0,
		Len:   uint16(unsafe.Sizeof(uint32(0))),
		Flags: 0,
	}

	// Create message
	buf := make([]byte, nlh.Len)
	*(*nlMsgHdr)(unsafe.Pointer(&buf[0])) = nlh
	*(*cnMsgHdr)(unsafe.Pointer(&buf[unsafe.Sizeof(nlMsgHdr{})])) = cnh
	*(*uint32)(unsafe.Pointer(&buf[unsafe.Sizeof(nlMsgHdr{})+unsafe.Sizeof(cnMsgHdr{})])) = PROC_CN_MCAST_LISTEN

	// Send message
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0, // Send to kernel
	}
	if err := syscall.Sendto(m.sock, buf, 0, addr); err != nil {
		return fmt.Errorf("failed to send netlink message: %w", err)
	}

	return nil
}

// Stop stops monitoring process execution
func (m *ProcessMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.logger.Info("Stopping process monitor")

	// Signal the monitoring goroutine to stop
	close(m.stopCh)

	// Wait for it to exit
	m.wg.Wait()

	// Close the socket
	syscall.Close(m.sock)

	m.running = false
	m.logger.Debug("Process monitor stopped")

	return nil
}

// monitor handles process events
func (m *ProcessMonitor) monitor() {
	defer m.wg.Done()

	buf := make([]byte, 4096)

	for {
		select {
		case <-m.stopCh:
			return
		default:
			// Read from socket
			n, _, err := syscall.Recvfrom(m.sock, buf, 0)
			if err != nil {
				// Check if we're shutting down
				select {
				case <-m.stopCh:
					return
				default:
					m.logger.Errorf("Error reading from netlink: %v", err)
					continue
				}
			}

			// Process the message
			if err := m.processNetlinkMessage(buf[:n]); err != nil {
				m.logger.Errorf("Error processing netlink message: %v", err)
			}
		}
	}
}

// processNetlinkMessage handles a netlink message containing process events
func (m *ProcessMonitor) processNetlinkMessage(buf []byte) error {
	// Parse netlink header
	if len(buf) < int(unsafe.Sizeof(nlMsgHdr{})) {
		return errors.New("message too short for netlink header")
	}

	// Skip netlink header
	buf = buf[unsafe.Sizeof(nlMsgHdr{}):]

	// Parse connector header
	if len(buf) < int(unsafe.Sizeof(cnMsgHdr{})) {
		return errors.New("message too short for connector header")
	}

	// Get connector header
	cnMsg := (*cnMsgHdr)(unsafe.Pointer(&buf[0]))

	// Make sure it's a proc connector message
	if cnMsg.Id[0] != CN_IDX_PROC || cnMsg.Id[1] != CN_VAL_PROC {
		return nil // Not a proc connector message, ignore
	}

	// Skip connector header
	buf = buf[unsafe.Sizeof(cnMsgHdr{}):]

	// Parse process event header
	if len(buf) < int(unsafe.Sizeof(procEventHdr{})) {
		return errors.New("message too short for proc event header")
	}

	// Get event header
	evtHdr := (*procEventHdr)(unsafe.Pointer(&buf[0]))

	// Skip event header
	buf = buf[unsafe.Sizeof(procEventHdr{}):]

	// Handle based on event type
	switch evtHdr.What {
	case PROC_EVENT_EXEC:
		if len(buf) < int(unsafe.Sizeof(execProcEvent{})) {
			return errors.New("message too short for exec event")
		}

		// Get exec event
		execEvt := (*execProcEvent)(unsafe.Pointer(&buf[0]))

		// Handle the exec event
		go m.handleExecEvent(int(execEvt.ProcessPid))
	}

	return nil
}

// handleExecEvent processes a process execution event
func (m *ProcessMonitor) handleExecEvent(pid int) {
	// Check if this is a process we're interested in
	execPath, err := m.getProcessExePath(pid)
	if err != nil {
		return // Can't get process path, ignore
	}

	m.logger.Debugf("Process executed: PID=%d, Path=%s", pid, execPath)

	// Check if this is a blocked app
	for _, blockedApp := range m.config.BlockedApps {
		if strings.HasPrefix(execPath, blockedApp.Path) {
			// Found a match, handle it
			m.logger.Infof("Blocked application detected: %s (PID: %d)", execPath, pid)
			m.handleBlockedApp(pid, blockedApp, execPath)
			break
		}
	}
}

// getProcessExePath gets the executable path for a process
func (m *ProcessMonitor) getProcessExePath(pid int) (string, error) {
	// Read the symlink to get the executable path
	execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}

	return execPath, nil
}

// handleBlockedApp processes a blocked application execution
func (m *ProcessMonitor) handleBlockedApp(pid int, app config.BlockedApp, execPath string) {
	// Check if we're already handling this PID
	m.handledMu.Lock()
	if _, exists := m.handledPids[pid]; exists {
		m.handledMu.Unlock()
		m.logger.Debugf("Already handling PID %d, skipping", pid)
		return // Already being handled
	}

	// Mark as being handled
	m.handledPids[pid] = execPath
	m.handledMu.Unlock()

	// Make sure we clean up when done
	defer func() {
		m.handledMu.Lock()
		delete(m.handledPids, pid)
		m.handledMu.Unlock()
	}()

	// Stop the process
	m.logger.Infof("Suspending process %d (%s)", pid, execPath)
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		m.logger.Errorf("Failed to stop process %d: %v", pid, err)
		return
	}

	// Get display name
	displayName := app.DisplayName
	if displayName == "" {
		displayName = filepath.Base(execPath)
	}

	// Show authentication dialog
	m.logger.Infof("Showing authentication dialog for %s", displayName)
	password, ok, err := m.guiManager.ShowAuthDialog(displayName)
	if err != nil {
		m.logger.Errorf("Error showing auth dialog: %v", err)
		// Kill the process and return
		syscall.Kill(pid, syscall.SIGTERM)
		m.logger.Infof("Process %d terminated due to authentication dialog error", pid)
		return
	}

	// If dialog was cancelled
	if !ok {
		m.logger.Infof("Authentication cancelled by user for %s", displayName)
		// Kill the process
		syscall.Kill(pid, syscall.SIGTERM)
		m.logger.Debug("Process terminated due to cancelled authentication")
		return
	}

	// Authenticate
	m.logger.Debug("Verifying authentication")
	authenticated, err := m.authenticator.Authenticate([]byte(password))
	if err != nil {
		m.logger.Errorf("Authentication error: %v", err)
		// Kill the process
		syscall.Kill(pid, syscall.SIGTERM)
		m.logger.Debug("Process terminated due to authentication error")
		return
	}

	if authenticated {
		// Authentication successful, let the process continue
		m.logger.Infof("Authentication successful for %s, resuming process %d", displayName, pid)
		syscall.Kill(pid, syscall.SIGCONT)
	} else {
		// Authentication failed, kill the process
		m.logger.Infof("Authentication failed for %s, terminating process %d", displayName, pid)
		syscall.Kill(pid, syscall.SIGTERM)
	}
}
