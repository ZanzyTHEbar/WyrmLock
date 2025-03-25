package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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

// ProcessInfo holds information about a monitored process
type ProcessInfo struct {
	PID       int    // Process ID
	Command   string // Full path to executable
	ExecHash  string // SHA-256 hash of executable
	ParentPID int    // Parent process ID
	Allowed   bool   // Whether the process is allowed to run
	StartTime int64  // Process start time for race condition prevention
	CmdLine   string // Full command line for verification
	State     string // Current process state
}

// ProcessState represents the current state of a process
const (
	ProcessStateRunning    = "running"
	ProcessStateSuspended  = "suspended"
	ProcessStateTerminated = "terminated"
)

// ProcessVerificationError represents process verification failures
type ProcessVerificationError struct {
	Reason string
	PID    int
	Detail string
}

func (e *ProcessVerificationError) Error() string {
	return fmt.Sprintf("process verification failed for PID %d: %s (%s)", e.PID, e.Reason, e.Detail)
}

// ProcessEventHandler is a callback function for process events
type ProcessEventHandler func(pid int, execPath string, displayName string)

// ProcessMonitor monitors process execution
type ProcessMonitor struct {
	config        *config.Config
	authenticator *auth.Authenticator
	guiManager    *gui.Manager
	sock          int
	running       bool
	mu            sync.Mutex
	wg            sync.WaitGroup
	stopCh        chan struct{}

	// Map of PIDs that are being handled
	handledPids map[int]string
	handledMu   sync.Mutex

	// Logging
	logger *logging.Logger

	// For daemon mode
	daemonMode     bool
	eventHandler   ProcessEventHandler
	eventHandlerMu sync.RWMutex

	// Add a field to track monitored processes
	monitoredProcesses map[int]ProcessInfo
	monitoredMu        sync.RWMutex
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
	guiManager, err := gui.NewManager(gui.GuiType(cfg.Auth.GuiType))
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
		config:             cfg,
		authenticator:      authenticator,
		guiManager:         guiManager,
		handledPids:        make(map[int]string),
		monitoredProcesses: make(map[int]ProcessInfo),
		stopCh:             make(chan struct{}),
		logger:             logger,
		daemonMode:         false,
	}, nil
}

// NewProcessMonitorDaemon creates a new process monitor in daemon mode
func NewProcessMonitorDaemon(cfg *config.Config, logger *logging.Logger) (*ProcessMonitor, error) {
	return &ProcessMonitor{
		config:             cfg,
		handledPids:        make(map[int]string),
		monitoredProcesses: make(map[int]ProcessInfo),
		stopCh:             make(chan struct{}),
		logger:             logger,
		daemonMode:         true,
	}, nil
}

// RegisterEventHandler registers a callback function for process events in daemon mode
func (m *ProcessMonitor) RegisterEventHandler(handler ProcessEventHandler) {
	m.eventHandlerMu.Lock()
	m.eventHandler = handler
	m.eventHandlerMu.Unlock()
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

// isBlockedApp checks if the given executable path is in the list of protected apps
func (m *ProcessMonitor) isBlockedApp(execPath string, pid int) (bool, string) {
	// Get absolute path
	absPath, err := filepath.Abs(execPath)
	if err != nil {
		m.logger.Warnf("Failed to get absolute path for %s: %v", execPath, err)
		return false, ""
	}

	// Clean the path
	cleanPath := filepath.Clean(absPath)

	// Get process hash for verification
	var execHash string
	if data, err := os.ReadFile(cleanPath); err == nil {
		h := sha256.New()
		h.Write(data)
		execHash = fmt.Sprintf("%x", h.Sum(nil))
	} else {
		m.logger.Warnf("Failed to calculate hash for %s: %v", cleanPath, err)
		return false, ""
	}

	// Get parent PID for logging
	ppid := 0
	if parentPID, err := m.getProcessParentPID(pid); err == nil {
		ppid = parentPID
	}

	// Check if this executable is protected
	for _, protectedPath := range m.config.Monitor.ProtectedApps {
		// Get absolute path for protected app
		protectedAbs, err := filepath.Abs(protectedPath)
		if err != nil {
			m.logger.Warnf("Failed to get absolute path for protected app %s: %v", protectedPath, err)
			continue
		}

		// Clean the protected path
		protectedClean := filepath.Clean(protectedAbs)

		// Check if paths match
		if cleanPath == protectedClean {
			m.logger.Debugf("Found protected app %s (PID: %d, PPID: %d, Hash: %s)",
				cleanPath, pid, ppid, execHash)
			return true, cleanPath
		}
	}

	return false, ""
}

// getFileHash computes the SHA-256 hash of a file
func (m *ProcessMonitor) getFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// getProcessParentPID returns the parent PID of a process
func (m *ProcessMonitor) getProcessParentPID(pid int) (int, error) {
	// Read the stat file which contains process info
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read process stat: %w", err)
	}

	// Parse the stat file - format is documented in proc(5)
	stat := string(statBytes)
	fields := strings.Fields(stat)
	if len(fields) < 4 {
		return 0, fmt.Errorf("invalid stat file format")
	}

	// Parent PID is the 4th field
	ppid, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, fmt.Errorf("failed to parse parent PID: %w", err)
	}

	return ppid, nil
}

// verifyProcess performs comprehensive process verification
func (m *ProcessMonitor) verifyProcess(pid int, expectedPath string) error {
	// Get current process info
	procInfo, err := m.getProcessInfo(pid)
	if err != nil {
		return &ProcessVerificationError{
			Reason: "failed to get process info",
			PID:    pid,
			Detail: err.Error(),
		}
	}

	// Verify process exists and matches expected path
	if procInfo.Command != expectedPath {
		return &ProcessVerificationError{
			Reason: "path mismatch",
			PID:    pid,
			Detail: fmt.Sprintf("expected %s, got %s", expectedPath, procInfo.Command),
		}
	}

	// Verify process start time matches (if we have it)
	if info, exists := m.monitoredProcesses[pid]; exists && info.StartTime > 0 {
		if info.StartTime != procInfo.StartTime {
			return &ProcessVerificationError{
				Reason: "start time mismatch",
				PID:    pid,
				Detail: "process has been replaced",
			}
		}
	}

	// Verify executable hash
	currentHash, err := m.getFileHash(procInfo.Command)
	if err != nil {
		return &ProcessVerificationError{
			Reason: "failed to get file hash",
			PID:    pid,
			Detail: err.Error(),
		}
	}

	if info, exists := m.monitoredProcesses[pid]; exists && info.ExecHash != "" {
		if info.ExecHash != currentHash {
			return &ProcessVerificationError{
				Reason: "executable hash mismatch",
				PID:    pid,
				Detail: fmt.Sprintf("expected %s, got %s", info.ExecHash, currentHash),
			}
		}
	}

	// Verify command line arguments haven't changed
	cmdLine, err := m.getProcessCmdLine(pid)
	if err != nil {
		return &ProcessVerificationError{
			Reason: "failed to get command line",
			PID:    pid,
			Detail: err.Error(),
		}
	}

	if info, exists := m.monitoredProcesses[pid]; exists && info.CmdLine != "" {
		if info.CmdLine != cmdLine {
			return &ProcessVerificationError{
				Reason: "command line mismatch",
				PID:    pid,
				Detail: fmt.Sprintf("expected %s, got %s", info.CmdLine, cmdLine),
			}
		}
	}

	return nil
}

// getProcessInfo retrieves comprehensive process information
func (m *ProcessMonitor) getProcessInfo(pid int) (*ProcessInfo, error) {
	// Get basic process info
	execPath, err := m.getProcessExePath(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process path: %w", err)
	}

	// Get process start time
	startTime, err := m.getProcessStartTime(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process start time: %w", err)
	}

	// Get command line
	cmdLine, err := m.getProcessCmdLine(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get command line: %w", err)
	}

	// Get parent PID
	ppid, err := m.getProcessParentPID(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent PID: %w", err)
	}

	// Get file hash
	hash, err := m.getFileHash(execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file hash: %w", err)
	}

	// Get process state
	state, err := m.getProcessState(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process state: %w", err)
	}

	return &ProcessInfo{
		PID:       pid,
		Command:   execPath,
		ExecHash:  hash,
		ParentPID: ppid,
		StartTime: startTime,
		CmdLine:   cmdLine,
		State:     state,
	}, nil
}

// getProcessStartTime retrieves the start time of a process
func (m *ProcessMonitor) getProcessStartTime(pid int) (int64, error) {
	// Read the stat file
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read process stat: %w", err)
	}

	// Parse the stat file
	stat := string(statBytes)
	fields := strings.Fields(stat)
	if len(fields) < 22 {
		return 0, fmt.Errorf("invalid stat file format")
	}

	// Start time is the 22nd field
	startTime, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse start time: %w", err)
	}

	return startTime, nil
}

// getProcessCmdLine retrieves the full command line of a process
func (m *ProcessMonitor) getProcessCmdLine(pid int) (string, error) {
	// Read the cmdline file
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineBytes, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", fmt.Errorf("failed to read process cmdline: %w", err)
	}

	// cmdline uses null bytes to separate arguments
	args := strings.Split(string(cmdlineBytes), "\x00")
	// Remove empty strings
	var cleanArgs []string
	for _, arg := range args {
		if arg != "" {
			cleanArgs = append(cleanArgs, arg)
		}
	}

	return strings.Join(cleanArgs, " "), nil
}

// getProcessState retrieves the current state of a process
func (m *ProcessMonitor) getProcessState(pid int) (string, error) {
	// Read the stat file
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return "", fmt.Errorf("failed to read process stat: %w", err)
	}

	// Parse the stat file
	stat := string(statBytes)
	fields := strings.Fields(stat)
	if len(fields) < 3 {
		return "", fmt.Errorf("invalid stat file format")
	}

	// State is the 3rd field
	switch fields[2] {
	case "R":
		return ProcessStateRunning, nil
	case "S", "D":
		return ProcessStateRunning, nil // Also count sleeping as running
	case "T":
		return ProcessStateSuspended, nil
	case "Z", "X":
		return ProcessStateTerminated, nil
	default:
		return "unknown", nil
	}
}

// handleExecEvent processes a process execution event
func (m *ProcessMonitor) handleExecEvent(pid int) {
	// Get comprehensive process info
	procInfo, err := m.getProcessInfo(pid)
	if err != nil {
		m.logger.Debugf("Could not get process info for PID %d: %v", pid, err)
		return
	}

	m.logger.Debugf("Process executed: %+v", procInfo)

	// Check if this is a protected app
	isBlocked, appPath := m.isBlockedApp(procInfo.Command, pid)
	if isBlocked {
		m.logger.Infof("Protected application detected: %s (PID: %d, Parent PID: %d, Hash: %s)",
			procInfo.Command, pid, procInfo.ParentPID, procInfo.ExecHash)

		// Update monitored processes list with enhanced information
		m.updateMonitoredProcessEnhanced(pid, appPath, false, procInfo.ExecHash, procInfo.ParentPID)

		// Handle the protected app
		m.handleBlockedApp(pid, appPath)
	} else {
		// Log non-protected process for debugging
		m.logger.Debugf("Non-protected process: %s (PID: %d, Parent PID: %d)",
			procInfo.Command, pid, procInfo.ParentPID)
	}
}

// getProcessExePath returns the executable path of a process
func (m *ProcessMonitor) getProcessExePath(pid int) (string, error) {
	// Read the exe symlink in /proc
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("failed to read process exe path: %w", err)
	}
	return exePath, nil
}

// updateMonitoredProcessEnhanced adds or updates a process in the monitored processes map with enhanced info
func (m *ProcessMonitor) updateMonitoredProcessEnhanced(pid int, command string, allowed bool, execHash string, parentPID int) {
	m.monitoredMu.Lock()
	defer m.monitoredMu.Unlock()

	m.monitoredProcesses[pid] = ProcessInfo{
		PID:       pid,
		Command:   command,
		Allowed:   allowed,
		ExecHash:  execHash,
		ParentPID: parentPID,
	}
}

// removeMonitoredProcess removes a process from the monitored processes list
func (m *ProcessMonitor) removeMonitoredProcess(pid int) {
	m.monitoredMu.Lock()
	defer m.monitoredMu.Unlock()
	delete(m.monitoredProcesses, pid)
}

// handleBlockedApp processes a protected application execution
func (m *ProcessMonitor) handleBlockedApp(pid int, execPath string) {
	// Check if we're already handling this PID
	m.handledMu.Lock()
	if _, exists := m.handledPids[pid]; exists {
		m.handledMu.Unlock()
		m.logger.Debugf("Already handling PID %d, skipping", pid)
		return
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

	// Verify process integrity
	if err := m.verifyProcess(pid, execPath); err != nil {
		m.logger.Warnf("Process verification failed: %v", err)
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			m.logger.Errorf("Failed to terminate unverified process %d: %v", pid, err)
		}
		return
	}

	// Get process info for enhanced tracking
	procInfo, err := m.getProcessInfo(pid)
	if err != nil {
		m.logger.Warnf("Failed to get process info: %v", err)
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			m.logger.Errorf("Failed to terminate process %d: %v", pid, err)
		}
		return
	}

	// Stop the process
	m.logger.Infof("Suspending process %d (%s, parent PID: %d)", pid, execPath, procInfo.ParentPID)
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		m.logger.Errorf("Failed to stop process %d: %v", pid, err)
		return
	}

	// Update process state
	procInfo.State = ProcessStateSuspended
	m.updateMonitoredProcessEnhanced(pid, execPath, false, procInfo.ExecHash, procInfo.ParentPID)

	// Get display name
	displayName := filepath.Base(execPath)

	// Handle daemon mode
	if m.daemonMode {
		m.eventHandlerMu.RLock()
		handler := m.eventHandler
		m.eventHandlerMu.RUnlock()

		if handler != nil {
			go handler(pid, execPath, displayName)
		} else {
			m.logger.Error("No event handler registered in daemon mode")
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
				m.logger.Errorf("Failed to terminate process %d: %v", pid, err)
			}
		}
		return
	}

	// Handle authentication in normal mode
	if err := m.handleAuthentication(pid, execPath, displayName); err != nil {
		m.logger.Errorf("Authentication failed: %v", err)
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			m.logger.Errorf("Failed to terminate process %d: %v", pid, err)
		}
		m.removeMonitoredProcess(pid)
	}
}

// handleAuthentication handles the authentication process for a protected app
func (m *ProcessMonitor) handleAuthentication(pid int, execPath, displayName string) error {
	// Check remaining attempts
	remainingAttempts := 0
	if m.authenticator != nil {
		remainingAttempts = m.authenticator.GetRemainingAttempts(execPath)
		if remainingAttempts <= 0 {
			return fmt.Errorf("no authentication attempts remaining for %s", displayName)
		}
	}

	// Show authentication dialog
	m.logger.Infof("Showing authentication dialog for %s (attempts remaining: %d)", displayName, remainingAttempts)
	password, ok, err := m.guiManager.ShowAuthDialog(displayName)
	if err != nil {
		return fmt.Errorf("error showing auth dialog: %w", err)
	}

	if !ok {
		return fmt.Errorf("authentication cancelled by user")
	}

	// Verify process hasn't changed during authentication
	if err := m.verifyProcess(pid, execPath); err != nil {
		return fmt.Errorf("process verification failed after dialog: %w", err)
	}

	// Authenticate
	m.logger.Debug("Verifying authentication")
	authenticated, err := m.authenticator.Authenticate([]byte(password), execPath)
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}

	if !authenticated {
		remainingAttempts = m.authenticator.GetRemainingAttempts(execPath)
		return fmt.Errorf("authentication failed (attempts remaining: %d)", remainingAttempts)
	}

	// Final verification before resuming
	if err := m.verifyProcess(pid, execPath); err != nil {
		return fmt.Errorf("final process verification failed: %w", err)
	}

	// Resume the process
	m.logger.Infof("Authentication successful for %s, resuming process %d", displayName, pid)
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return fmt.Errorf("failed to resume process: %w", err)
	}

	// Update process status
	procInfo, err := m.getProcessInfo(pid)
	if err != nil {
		return fmt.Errorf("failed to get final process info: %w", err)
	}

	procInfo.Allowed = true
	procInfo.State = ProcessStateRunning
	m.updateMonitoredProcessEnhanced(pid, execPath, true, procInfo.ExecHash, procInfo.ParentPID)

	return nil
}

// ResumeProcess resumes a suspended process (for daemon mode)
func (m *ProcessMonitor) ResumeProcess(pid int) error {
	m.logger.Infof("Resuming process %d", pid)
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return fmt.Errorf("failed to resume process %d: %w", pid, err)
	}

	// Update status in our tracked processes
	m.handledMu.Lock()
	execPath, exists := m.handledPids[pid]
	m.handledMu.Unlock()

	if exists {
		// Get the enhanced info
		execHash := ""
		parentPID := 0

		// Try to get hash if available
		if hash, err := m.getFileHash(execPath); err == nil {
			execHash = hash
		}

		// Try to get parent PID
		if ppid, err := m.getProcessParentPID(pid); err == nil {
			parentPID = ppid
		}

		m.updateMonitoredProcessEnhanced(pid, execPath, true, execHash, parentPID)
	}

	return nil
}

// TerminateProcess terminates a process (for daemon mode)
func (m *ProcessMonitor) TerminateProcess(pid int) error {
	m.logger.Infof("Terminating process %d", pid)
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to terminate process %d: %w", pid, err)
	}

	// Remove from tracked processes
	m.removeMonitoredProcess(pid)

	return nil
}

// PollProcesses returns the current state of monitored processes
func (m *ProcessMonitor) PollProcesses() ([]ProcessInfo, error) {
	m.monitoredMu.RLock()
	defer m.monitoredMu.RUnlock()

	// Create a copy of the monitored processes
	processes := make([]ProcessInfo, 0, len(m.monitoredProcesses))
	for _, process := range m.monitoredProcesses {
		processes = append(processes, process)
	}

	return processes, nil
}
