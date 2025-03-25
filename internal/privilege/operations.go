package privilege

import (
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"applock-go/internal/logging"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// OperationType defines the type of operation to perform
type OperationType string

const (
	// Operation types
	OpHashComputation OperationType = "hash_computation"
	OpProcessControl  OperationType = "process_control"
	OpSocketCreation  OperationType = "socket_creation"
	OpConfiguration   OperationType = "configuration"
	OpAuthentication  OperationType = "authentication"
	OpMonitoring      OperationType = "process_monitoring"
)

// OperationRequest represents a request to perform a privileged operation
type OperationRequest struct {
	Type      OperationType     `json:"type"`
	Arguments map[string]string `json:"arguments"`
}

// OperationResponse represents the response from a privileged operation
type OperationResponse struct {
	Success bool              `json:"success"`
	Error   string            `json:"error,omitempty"`
	Results map[string]string `json:"results,omitempty"`
}

// OperationHandler handles privileged operations
type OperationHandler struct {
	logger        *logging.Logger
	privManager   *PrivilegeManager
	helperBinary  string
	childPID      int
	isPrivileged  bool
	isInitialized bool
}

// NewOperationHandler creates a new operation handler
func NewOperationHandler(logger *logging.Logger, privManager *PrivilegeManager) *OperationHandler {
	return &OperationHandler{
		logger:       logger,
		privManager:  privManager,
		helperBinary: "/usr/sbin/applock-helper",
		isPrivileged: os.Geteuid() == 0,
	}
}

// InitializeHelper initializes the privilege helper process if needed
func (h *OperationHandler) InitializeHelper() error {
	if h.isInitialized {
		return nil
	}

	// If we're running as root, we can perform operations directly
	if h.isPrivileged {
		h.isInitialized = true
		return nil
	}

	// Check if helper exists
	if _, err := os.Stat(h.helperBinary); os.IsNotExist(err) {
		return fmt.Errorf("helper binary not found: %s", h.helperBinary)
	}

	h.isInitialized = true
	return nil
}

// ExecuteOperation executes a privileged operation
func (h *OperationHandler) ExecuteOperation(req OperationRequest) (*OperationResponse, error) {
	// Initialize if needed
	if !h.isInitialized {
		if err := h.InitializeHelper(); err != nil {
			return nil, fmt.Errorf("failed to initialize helper: %w", err)
		}
	}

	// Check if the operation requires privileges
	requiresPrivilege, requiredCaps := h.privManager.IsOperationPrivileged(string(req.Type))

	// If we're running as unprivileged and operation requires privileges,
	// delegate to the helper process
	if !h.isPrivileged && requiresPrivilege {
		return h.delegateToHelper(req)
	}

	// Execute the operation directly
	return h.executeDirectly(req, requiredCaps)
}

// delegateToHelper delegates an operation to the privileged helper process
func (h *OperationHandler) delegateToHelper(req OperationRequest) (*OperationResponse, error) {
	// Convert request to JSON for IPC
	// Implementation would use JSON over IPC to communicate with helper
	// For now, return a mock response
	h.logger.Debugf("Delegating operation %s to privileged helper", req.Type)

	response := &OperationResponse{
		Success: false,
		Error:   "Helper process communication not yet implemented",
	}

	return response, nil
}

// executeDirectly executes an operation directly with current privileges
func (h *OperationHandler) executeDirectly(req OperationRequest, requiredCaps []Capability) (*OperationResponse, error) {
	h.logger.Debugf("Executing operation %s directly", req.Type)

	// Implement specific operation handlers
	switch req.Type {
	case OpHashComputation:
		return h.handleHashComputation(req)
	case OpProcessControl:
		return h.handleProcessControl(req)
	case OpSocketCreation:
		return h.handleSocketCreation(req)
	case OpConfiguration:
		return h.handleConfiguration(req)
	case OpAuthentication:
		return h.handleAuthentication(req)
	case OpMonitoring:
		return h.handleProcessMonitoring(req)
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown operation type: %s", req.Type),
		}, nil
	}
}

// handleHashComputation handles computing file hashes
func (h *OperationHandler) handleHashComputation(req OperationRequest) (*OperationResponse, error) {
	filePath, ok := req.Arguments["file_path"]
	if !ok {
		return &OperationResponse{
			Success: false,
			Error:   "missing file_path argument",
		}, nil
	}
	
	// Get the hash algorithm to use
	algorithm, ok := req.Arguments["algorithm"]
	if !ok {
		algorithm = "sha256" // Default to SHA-256
	}
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("file not found: %s", filePath),
		}, nil
	}
	
	// Import monitor package to reuse the hash computation function
	// This would typically require importing the monitor package
	// but for simplicity we'll compute the hash here
	
	h.logger.Debugf("Computing %s hash for %s", algorithm, filePath)
	
	var hashValue string
	var err error
	
	// Open the file for reading
	file, err := os.Open(filePath)
	if err != nil {
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to open file: %v", err),
		}, nil
	}
	defer file.Close()
	
	// Compute hash based on algorithm
	switch algorithm {
	case "sha256":
		// Create SHA-256 hash
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to compute hash: %v", err),
			}, nil
		}
		hashValue = hex.EncodeToString(hasher.Sum(nil))
		
	case "sha512":
		// Create SHA-512 hash
		hasher := sha512.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to compute hash: %v", err),
			}, nil
		}
		hashValue = hex.EncodeToString(hasher.Sum(nil))
		
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported hash algorithm: %s", algorithm),
		}, nil
	}
	
	return &OperationResponse{
		Success: true,
		Results: map[string]string{
			"hash_type": algorithm,
			"hash":      hashValue,
			"file_path": filePath,
		},
	}, nil
}

// handleProcessControl handles process control operations
func (h *OperationHandler) handleProcessControl(req OperationRequest) (*OperationResponse, error) {
	// Get operation arguments
	action, ok := req.Arguments["action"]
	if !ok {
		return &OperationResponse{
			Success: false,
			Error:   "missing action argument",
		}, nil
	}
	
	pidStr, ok := req.Arguments["pid"]
	if !ok {
		return &OperationResponse{
			Success: false,
			Error:   "missing pid argument",
		}, nil
	}
	
	// Convert PID string to integer
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid pid: %s", pidStr),
		}, nil
	}
	
	h.logger.Debugf("Process control operation: %s for PID %d", action, pid)
	
	// Perform requested action
	switch action {
	case "suspend":
		// Send SIGSTOP to the process to suspend it
		if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to suspend process: %v", err),
			}, nil
		}
		
		h.logger.Infof("Successfully suspended process with PID %d", pid)
		
	case "resume":
		// Send SIGCONT to the process to resume it
		if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to resume process: %v", err),
			}, nil
		}
		
		h.logger.Infof("Successfully resumed process with PID %d", pid)
		
	case "terminate":
		// Send SIGTERM to the process to terminate it
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to terminate process: %v", err),
			}, nil
		}
		
		h.logger.Infof("Successfully sent termination signal to process with PID %d", pid)
		
	case "kill":
		// Send SIGKILL to the process to forcefully kill it
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to kill process: %v", err),
			}, nil
		}
		
		h.logger.Infof("Successfully killed process with PID %d", pid)
		
	case "check":
		// Check if the process exists
		process, err := os.FindProcess(pid)
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("process not found: %v", err),
			}, nil
		}
		
		// On Unix, FindProcess always succeeds, so we need to send signal 0
		// to check if the process exists
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("process not running: %v", err),
			}, nil
		}
		
		h.logger.Debugf("Process with PID %d exists", pid)
		
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported action: %s", action),
		}, nil
	}
	
	return &OperationResponse{
		Success: true,
		Results: map[string]string{
			"action": action,
			"pid":    pidStr,
		},
	}, nil
}

// handleSocketCreation handles socket creation operations
func (h *OperationHandler) handleSocketCreation(req OperationRequest) (*OperationResponse, error) {
	// Get operation arguments
	action, ok := req.Arguments["action"]
	if !ok {
		return &OperationResponse{
			Success: false,
			Error:   "missing action argument",
		}, nil
	}
	
	h.logger.Debugf("Socket operation: %s", action)
	
	switch action {
	case "create":
		// Get socket path
		socketPath, ok := req.Arguments["socket_path"]
		if !ok {
			socketPath = HelperSocketPath // Use default path if not specified
		}
		
		// Create socket directory if it doesn't exist
		socketDir := filepath.Dir(socketPath)
		if err := os.MkdirAll(socketDir, 0755); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to create socket directory: %v", err),
			}, nil
		}
		
		// Remove existing socket if it exists
		if _, err := os.Stat(socketPath); err == nil {
			if err := os.Remove(socketPath); err != nil {
				return &OperationResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to remove existing socket: %v", err),
				}, nil
			}
		}
		
		// Create Unix domain socket
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to create socket: %v", err),
			}, nil
		}
		
		// Set socket permissions
		if err := os.Chmod(socketPath, 0600); err != nil {
			socket.Close()
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to set socket permissions: %v", err),
			}, nil
		}
		
		// Don't close the socket, the caller should manage its lifecycle
		h.logger.Infof("Successfully created socket at %s", socketPath)
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"socket_path": socketPath,
			},
		}, nil
		
	case "remove":
		// Get socket path
		socketPath, ok := req.Arguments["socket_path"]
		if !ok {
			socketPath = HelperSocketPath // Use default path if not specified
		}
		
		// Check if socket exists
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			// Socket doesn't exist, which is fine
			return &OperationResponse{
				Success: true,
				Results: map[string]string{
					"socket_path": socketPath,
					"status":      "not_exists",
				},
			}, nil
		}
		
		// Remove the socket
		if err := os.Remove(socketPath); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to remove socket: %v", err),
			}, nil
		}
		
		h.logger.Infof("Successfully removed socket at %s", socketPath)
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"socket_path": socketPath,
				"status":      "removed",
			},
		}, nil
		
	case "check":
		// Get socket path
		socketPath, ok := req.Arguments["socket_path"]
		if !ok {
			socketPath = HelperSocketPath // Use default path if not specified
		}
		
		// Check if socket exists
		info, err := os.Stat(socketPath)
		if os.IsNotExist(err) {
			return &OperationResponse{
				Success: true,
				Results: map[string]string{
					"socket_path": socketPath,
					"exists":      "false",
				},
			}, nil
		}
		
		// Check if it's a socket
		mode := info.Mode()
		if mode&os.ModeSocket == 0 {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("%s exists but is not a socket", socketPath),
			}, nil
		}
		
		// Check socket permissions
		perms := mode.Perm()
		permStr := fmt.Sprintf("%04o", perms)
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"socket_path": socketPath,
				"exists":      "true",
				"permissions": permStr,
			},
		}, nil
		
	case "restore_privileges":
		// This is a special operation to restore privileges when needed
		// Can be used by the daemon for cleanup operations
		
		// We'll just set capabilities for now
		requiredCaps := []Capability{
			CAP_NET_ADMIN,
			CAP_SYS_PTRACE,
			CAP_SYS_ADMIN,
			CAP_CHOWN,
			CAP_SETUID,
			CAP_SETGID,
			CAP_SETPCAP,
		}
		
		if err := h.privManager.setCapabilities(requiredCaps); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to restore capabilities: %v", err),
			}, nil
		}
		
		h.logger.Info("Successfully restored capabilities")
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"status": "privileges_restored",
			},
		}, nil
		
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported socket action: %s", action),
		}, nil
	}
}

// handleConfiguration handles configuration operations
func (h *OperationHandler) handleConfiguration(req OperationRequest) (*OperationResponse, error) {
	// TODO: Implementation details...
	return &OperationResponse{
		Success: true,
	}, nil
}

// handleAuthentication handles authentication operations
func (h *OperationHandler) handleAuthentication(req OperationRequest) (*OperationResponse, error) {
	// TODO: Implementation details...
	return &OperationResponse{
		Success: true,
	}, nil
}

// handleProcessMonitoring handles process monitoring operations
func (h *OperationHandler) handleProcessMonitoring(req OperationRequest) (*OperationResponse, error) {
	// Get operation arguments
	action, ok := req.Arguments["action"]
	if !ok {
		return &OperationResponse{
			Success: false,
			Error:   "missing action argument",
		}, nil
	}
	
	h.logger.Debugf("Process monitoring operation: %s", action)
	
	switch action {
	case "start":
		// This would normally start the process monitor
		// For this implementation, we'll assume the caller has already created a
		// ProcessMonitor instance and is just using this for privilege escalation
		
		// Check if netlink socket creation requires capabilities
		// This operation requires CAP_NET_ADMIN
		
		// We should have required capabilities at this point
		if err := h.privManager.VerifyCapabilities(); err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("capability verification failed: %v", err),
			}, nil
		}
		
		h.logger.Info("Process monitoring capabilities verified")
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"status": "monitoring_ready",
			},
		}, nil
		
	case "stop":
		// This would normally stop the process monitor
		// For this implementation, we'll assume the caller is handling the actual
		// stopping and is just using this for cleanup
		
		h.logger.Info("Process monitoring stopped")
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"status": "monitoring_stopped",
			},
		}, nil
		
	case "verify_process":
		// Get the PID and application path
		pidStr, ok := req.Arguments["pid"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing pid argument",
			}, nil
		}
		
		appPath, ok := req.Arguments["app_path"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing app_path argument",
			}, nil
		}
		
		// Convert PID string to integer
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid pid: %s", pidStr),
			}, nil
		}
		
		// Check if the process exists
		process, err := os.FindProcess(pid)
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("process not found: %v", err),
				Results: map[string]string{
					"pid":     pidStr,
					"exists":  "false",
					"matched": "false",
				},
			}, nil
		}
		
		// On Unix, FindProcess always succeeds, so we need to send signal 0
		// to check if the process exists
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("process not running: %v", err),
				Results: map[string]string{
					"pid":     pidStr,
					"exists":  "false",
					"matched": "false",
				},
			}, nil
		}
		
		// Check if the executable path matches
		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return &OperationResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to read process executable path: %v", err),
				Results: map[string]string{
					"pid":     pidStr,
					"exists":  "true",
					"matched": "unknown",
				},
			}, nil
		}
		
		matched := exePath == appPath
		
		// Check if hash verification is requested
		verifyHash := false
		hashStr, ok := req.Arguments["verify_hash"]
		if ok && (hashStr == "true" || hashStr == "1") {
			verifyHash = true
		}
		
		var hashMatches bool
		var hashValue string
		
		// Compute hash if requested
		if verifyHash {
			// Get expected hash
			expectedHash, ok := req.Arguments["expected_hash"]
			if !ok {
				return &OperationResponse{
					Success: false,
					Error:   "verify_hash is true but expected_hash is missing",
				}, nil
			}
			
			// Get algorithm
			algorithm, ok := req.Arguments["hash_algorithm"]
			if !ok {
				algorithm = "sha256" // Default to SHA-256
			}
			
			// Compute hash
			file, err := os.Open(exePath)
			if err != nil {
				return &OperationResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to open executable for hashing: %v", err),
				}, nil
			}
			defer file.Close()
			
			var hasher hash.Hash
			
			switch algorithm {
			case "sha256":
				hasher = sha256.New()
			case "sha512":
				hasher = sha512.New()
			default:
				return &OperationResponse{
					Success: false,
					Error:   fmt.Sprintf("unsupported hash algorithm: %s", algorithm),
				}, nil
			}
			
			if _, err := io.Copy(hasher, file); err != nil {
				return &OperationResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to compute hash: %v", err),
				}, nil
			}
			
			hashValue = hex.EncodeToString(hasher.Sum(nil))
			hashMatches = hashValue == expectedHash
			
			h.logger.Debugf("Hash verification for PID %d: expected=%s, actual=%s, matches=%v",
				pid, expectedHash, hashValue, hashMatches)
		}
		
		h.logger.Debugf("Process verification for PID %d: path=%s, exists=true, matched=%v",
			pid, exePath, matched)
		
		results := map[string]string{
			"pid":     pidStr,
			"exists":  "true",
			"matched": fmt.Sprintf("%v", matched),
			"path":    exePath,
		}
		
		if verifyHash {
			results["hash_verified"] = fmt.Sprintf("%v", hashMatches)
			results["hash_value"] = hashValue
		}
		
		return &OperationResponse{
			Success: matched,
			Results: results,
		}, nil
		
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported monitoring action: %s", action),
		}, nil
	}
}

// StartHelperProcess starts a new privileged helper process
func (h *OperationHandler) StartHelperProcess() error {
	if h.childPID > 0 {
		// Helper already running
		return nil
	}

	// Use a secure method to execute the helper
	cmd := exec.Command(h.helperBinary, "--daemon")
	
	// Set the process to a new process group to avoid signals from parent
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start helper process: %w", err)
	}

	h.childPID = cmd.Process.Pid
	h.logger.Infof("Started privileged helper process with PID %d", h.childPID)

	return nil
}

// StopHelperProcess stops the privileged helper process
func (h *OperationHandler) StopHelperProcess() error {
	if h.childPID <= 0 {
		// No helper running
		return nil
	}

	// Send a termination signal to the process
	process, err := os.FindProcess(h.childPID)
	if err != nil {
		return fmt.Errorf("failed to find helper process: %w", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to terminate helper process: %w", err)
	}

	h.logger.Infof("Stopped privileged helper process with PID %d", h.childPID)
	h.childPID = 0

	return nil
} 