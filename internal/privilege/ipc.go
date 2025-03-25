package privilege

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"applock-go/internal/logging"
)

const (
	// HelperSocketPath is the default path for the Unix socket used for privileged operations
	HelperSocketPath = "/run/applock-helper.sock"
	
	// DefaultHelperBinary is the default path to the helper binary
	DefaultHelperBinary = "/usr/local/bin/applock-helper"
	
	// MaxConnectRetries is the maximum number of connection retries
	MaxConnectRetries = 5
	
	// ConnectRetryDelay is the delay between connection retries
	ConnectRetryDelay = 200 * time.Millisecond
)

// HelperClient manages communication with the helper process
type HelperClient struct {
	socketPath string
	helperPath string
	logger     *logging.Logger
	conn       net.Conn
}

// NewHelperClient creates a new client for communicating with the helper
func NewHelperClient(logger *logging.Logger) *HelperClient {
	return &HelperClient{
		socketPath: HelperSocketPath,
		helperPath: DefaultHelperBinary,
		logger:     logger,
	}
}

// Connect establishes a connection to the helper socket
func (c *HelperClient) Connect() error {
	var err error
	
	// Check if helper is running by trying to connect
	for i := 0; i < MaxConnectRetries; i++ {
		c.conn, err = net.Dial("unix", c.socketPath)
		if err == nil {
			return nil
		}
		
		// If we can't connect, try to start the helper
		if i == 0 {
			c.logger.Info("Helper not running, attempting to start it")
			if err := c.startHelper(); err != nil {
				return fmt.Errorf("failed to start helper: %w", err)
			}
		}
		
		time.Sleep(ConnectRetryDelay)
	}
	
	return fmt.Errorf("failed to connect to helper after %d attempts: %w", 
		MaxConnectRetries, err)
}

// Disconnect closes the connection to the helper
func (c *HelperClient) Disconnect() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// startHelper launches the helper process in daemon mode
func (c *HelperClient) startHelper() error {
	// Check if the helper binary exists
	if _, err := os.Stat(c.helperPath); os.IsNotExist(err) {
		return fmt.Errorf("helper binary not found at %s: %w", c.helperPath, err)
	}
	
	// Launch the helper in daemon mode
	cmd := exec.Command(c.helperPath, "--daemon")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start helper: %w", err)
	}
	
	// Don't wait for the helper to exit since it runs as a daemon
	return nil
}

// SendRequest sends an operation request to the helper and returns the response
func (c *HelperClient) SendRequest(req OperationRequest) (*OperationResponse, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}
	
	// Marshal the request to JSON
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Send the request
	_, err = c.conn.Write(reqData)
	if err != nil {
		c.Disconnect() // Connection might be broken, so disconnect
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	
	// Read the response (assuming a fixed buffer size for simplicity)
	// In a production environment, this should handle variable-length responses
	respData := make([]byte, 4096)
	n, err := c.conn.Read(respData)
	if err != nil {
		c.Disconnect() // Connection might be broken, so disconnect
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	// Unmarshal the response
	var resp OperationResponse
	if err := json.Unmarshal(respData[:n], &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp, nil
}

// ExecutePrivilegedOperation is a convenience method to send a request and receive a response
func (c *HelperClient) ExecutePrivilegedOperation(opType OperationType, args map[string]string) (*OperationResponse, error) {
	req := OperationRequest{
		Type:      opType,
		Arguments: args,
	}
	
	return c.SendRequest(req)
} 