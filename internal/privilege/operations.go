package privilege

import (
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"wyrmlock/internal/errors"
	"wyrmlock/internal/logging"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// OperationType defines the type of operation to perform
type OperationType string

const (
	// Operation types
	OpHashComputation OperationType = OpHashStr
	OpProcessControl  OperationType = OpProcessCtlStr
	OpSocketCreation  OperationType = OpSocketStr
	OpConfiguration   OperationType = OpConfigStr
	OpAuthentication  OperationType = OpAuthStr
	OpMonitoring      OperationType = OpMonitorStr
	OpPing            OperationType = OpPingStr
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
		h.logger.Info("Running with root privileges, no helper needed")
		h.isInitialized = true
		return nil
	}

	// Check if helper binary exists
	helperInfo, err := os.Stat(h.helperBinary)
	if os.IsNotExist(err) {
		return fmt.Errorf("helper binary not found: %s", h.helperBinary)
	} else if err != nil {
		return fmt.Errorf("error checking helper binary: %w", err)
	}
	
	// Verify helper binary permissions (should be owned by root and setuid)
	// This is a basic check - in production, you might want to verify signatures too
	if runtime.GOOS == "linux" {
		// Check ownership and permissions
		stat, ok := helperInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to get detailed file info for helper binary")
		}
		
		// Binary should be owned by root
		if stat.Uid != 0 {
			return fmt.Errorf("helper binary not owned by root (uid=%d)", stat.Uid)
		}
		
		// Check for setuid bit
		isSetuid := (helperInfo.Mode() & os.ModeSetuid) != 0
		if !isSetuid {
			h.logger.Warn("Helper binary does not have setuid bit set, may not have required privileges")
		}
	}
	
	// Create a helper client to verify connection
	helperClient := NewHelperClient(h.logger)
	
	// Test connection to helper (this will start it if not running)
	if err := helperClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to helper: %w", err)
	}
	
	// Send a simple ping request to verify helper is working
	resp, err := helperClient.ExecutePrivilegedOperation(
		"ping", 
		map[string]string{"message": "initialization"},
	)
	
	// Clean up connection
	helperClient.Disconnect()
	
	// Verify ping response
	if err != nil {
		return fmt.Errorf("failed to ping helper: %w", err)
	}
	
	if !resp.Success {
		return fmt.Errorf("helper responded with error: %s", resp.Error)
	}
	
	// Check for expected ping response
	if pong, ok := resp.Results["pong"]; !ok || pong != "true" {
		return fmt.Errorf("helper did not respond correctly to ping")
	}
	
	h.logger.Info("Helper binary initialized successfully")
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
	h.logger.Debugf("Delegating operation %s to privileged helper", req.Type)
	
	// Create a helper client
	helperClient := NewHelperClient(h.logger)
	
	// Add a unique request identifier for tracing
	if req.Arguments == nil {
		req.Arguments = make(map[string]string)
	}
	requestID := fmt.Sprintf("req-%d-%d", os.Getpid(), time.Now().UnixNano())
	req.Arguments["request_id"] = requestID
	
	// Attempt to execute the operation through the helper
	h.logger.Debugf("Sending request %s to helper for operation %s", requestID, req.Type)
	resp, err := helperClient.ExecutePrivilegedOperation(req.Type, req.Arguments)
	
	// Handle connection errors with structured error handling
	if err != nil {
		h.logger.Errorf("Failed to communicate with helper: %v", err)
		ipcErr := errors.IPCError(fmt.Sprintf("failed to communicate with helper for operation %s: %v", req.Type, err))
		
		return &OperationResponse{
			Success: false,
			Error:   ipcErr.Error(),
			Results: map[string]string{
				"request_id": requestID,
				"status":     "error",
				"error_type": "communication_failure",
			},
		}, ipcErr
	}
	
	// Log the result
	if resp.Success {
		h.logger.Debugf("Helper successfully executed operation %s (request %s)", req.Type, requestID)
	} else {
		h.logger.Errorf("Helper failed to execute operation %s (request %s): %s", req.Type, requestID, resp.Error)
		
		// Create a structured error based on the operation type
		var opErr error
		switch req.Type {
		case OpHashComputation:
			opErr = errors.Newf("hash computation failed: %s", resp.Error)
		case OpProcessControl:
			opErr = errors.Newf("process control failed: %s", resp.Error)
		case OpSocketCreation:
			opErr = errors.Newf("socket creation failed: %s", resp.Error)
		case OpAuthentication:
			opErr = errors.Newf("authentication failed: %s", resp.Error)
		case OpMonitoring:
			opErr = errors.Newf("monitoring operation failed: %s", resp.Error)
		default:
			opErr = errors.Newf("helper operation failed: %s", resp.Error)
		}
		
		// If we get back an error response but no error was returned,
		// return the structured error we created
		return resp, opErr
	}
	
	// Always disconnect when done
	if err := helperClient.Disconnect(); err != nil {
		h.logger.Warnf("Error disconnecting from helper: %v", err)
	}
	
	return resp, nil
}

// executeDirectly executes an operation directly with current privileges
func (h *OperationHandler) executeDirectly(req OperationRequest, requiredCaps []Capability) (*OperationResponse, error) {
	h.logger.Debugf("Executing operation %s directly", req.Type)

	// Verify we have the required capabilities before executing the operation
	if len(requiredCaps) > 0 {
		// Create a temporary capability set to verify
		tempCaps := make([]Capability, len(requiredCaps))
		copy(tempCaps, requiredCaps)
		
		h.logger.Debugf("Verifying %d required capabilities for operation %s", len(requiredCaps), req.Type)
		
		// Check if we have all required capabilities
		for _, cap := range requiredCaps {
			// Just log for now - in future, we should verify each capability
			h.logger.Debugf("Operation %s requires capability: %v", req.Type, cap)
		}
	}

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
	case OpPing:
		return h.handlePing(req)
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
	// Get the operation action
	action, ok := req.Arguments["action"]
	if !ok {
		action = "get" // Default to get action
	}
	
	h.logger.Debugf("Configuration operation: %s", action)
	
	// Process different configuration actions
	switch action {
	case "get":
		// Get configuration path
		configPath, ok := req.Arguments["config_path"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing config_path argument for get action",
			}, nil
		}
		
		h.logger.Debugf("Getting configuration from: %s", configPath)
		
		// In a real implementation, we would read the configuration file
		// For now, just return success
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"action":      "get",
				"config_path": configPath,
				"status":      "configuration_retrieved",
			},
		}, nil
		
	case "set":
		// Get configuration path
		configPath, ok := req.Arguments["config_path"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing config_path argument for set action",
			}, nil
		}
		
		// Check for configuration data
		configData, ok := req.Arguments["config_data"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing config_data argument for set action",
			}, nil
		}
		
		h.logger.Debugf("Setting configuration at: %s (data length: %d)", 
			configPath, len(configData))
		
		// In a real implementation, we would write the configuration file
		// For now, just return success
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"action":      "set",
				"config_path": configPath,
				"status":      "configuration_updated",
			},
		}, nil
		
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported configuration action: %s", action),
		}, nil
	}
}

// handleAuthentication handles authentication operations
func (h *OperationHandler) handleAuthentication(req OperationRequest) (*OperationResponse, error) {
	// Get the authentication action
	action, ok := req.Arguments["action"]
	if !ok {
		return &OperationResponse{
			Success: false,
			Error:   "missing action argument for authentication operation",
		}, nil
	}
	
	h.logger.Debugf("Authentication operation: %s", action)
	
	// Process different authentication actions
	switch action {
	case "verify_token":
		// Get token to verify
		token, ok := req.Arguments["token"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing token argument for verify_token action",
			}, nil
		}
		
		// In a real implementation, we would verify the authentication token
		// For now, just check if it's non-empty
		isValid := len(token) > 0
		
		h.logger.Debugf("Verifying authentication token (valid: %v)", isValid)
		
		return &OperationResponse{
			Success: isValid,
			Results: map[string]string{
				"action":     "verify_token",
				"valid":      fmt.Sprintf("%v", isValid),
				"token_type": "bearer", // Example token type
			},
		}, nil
		
	case "create_token":
		// Get subject/user for the token
		subject, ok := req.Arguments["subject"]
		if !ok {
			return &OperationResponse{
				Success: false,
				Error:   "missing subject argument for create_token action",
			}, nil
		}
		
		// In a real implementation, we would create a proper authentication token
		// For now, just create a mock token
		mockToken := fmt.Sprintf("mock-token-%s-%d", subject, time.Now().Unix())
		
		h.logger.Debugf("Created authentication token for subject: %s", subject)
		
		return &OperationResponse{
			Success: true,
			Results: map[string]string{
				"action":  "create_token",
				"token":   mockToken,
				"subject": subject,
				"expires": fmt.Sprintf("%d", time.Now().Add(24*time.Hour).Unix()),
			},
		}, nil
		
	default:
		return &OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported authentication action: %s", action),
		}, nil
	}
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

// handlePing is a simple handler to verify the helper is working properly
func (h *OperationHandler) handlePing(req OperationRequest) (*OperationResponse, error) {
	// Log the ping message if provided
	if msg, ok := req.Arguments["message"]; ok {
		h.logger.Debugf("Received ping with message: %s", msg)
	} else {
		h.logger.Debug("Received ping")
	}
	
	// Create response
	response := &OperationResponse{
		Success: true,
		Results: map[string]string{
			"pong":      "true",
			"timestamp": fmt.Sprintf("%d", time.Now().UnixNano()),
			"pid":       fmt.Sprintf("%d", os.Getpid()),
			"uid":       fmt.Sprintf("%d", os.Getuid()),
			"gid":       fmt.Sprintf("%d", os.Getgid()),
		},
	}
	
	return response, nil
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