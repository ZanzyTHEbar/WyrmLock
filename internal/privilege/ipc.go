package privilege

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"applock-go/internal/errors"
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
			c.logger.Debug("Successfully connected to helper socket")
			return nil
		}
		
		// If we can't connect, try to start the helper
		if i == 0 {
			c.logger.Info("Helper not running, attempting to start it")
			if err := c.startHelper(); err != nil {
				return errors.IPCError(fmt.Sprintf("failed to start helper: %v", err))
			}
		}
		
		c.logger.Debugf("Connection attempt %d failed, retrying in %v", i+1, ConnectRetryDelay)
		time.Sleep(ConnectRetryDelay)
	}
	
	// All retries failed, return a structured error
	return errors.IPCError(fmt.Sprintf("failed to connect to helper after %d attempts: %v", 
		MaxConnectRetries, err))
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
		return errors.Newf("helper binary not found at %s: %v", c.helperPath, err)
	}
	
	c.logger.Debugf("Starting helper binary at %s", c.helperPath)
	
	// Launch the helper in daemon mode
	cmd := exec.Command(c.helperPath, "--daemon")
	if err := cmd.Start(); err != nil {
		return errors.HelperError(fmt.Sprintf("failed to start helper process: %v", err))
	}
	
	c.logger.Info("Helper process started successfully")
	
	// Don't wait for the helper to exit since it runs as a daemon
	return nil
}

// SendRequest sends an operation request to the helper and returns the response
func (c *HelperClient) SendRequest(req OperationRequest) (*OperationResponse, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, errors.Wrap(err, "failed to connect to helper")
		}
	}
	
	// Add timestamp to request for freshness
	if req.Arguments == nil {
		req.Arguments = make(map[string]string)
	}
	req.Arguments["timestamp"] = fmt.Sprintf("%d", time.Now().UnixNano())
	
	// Marshal the request to JSON
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, errors.IPCError(fmt.Sprintf("failed to marshal request: %v", err))
	}
	
	// Create length-prefixed message for proper framing
	// Format: [4-byte length][message]
	msgLen := len(reqData)
	lenBytes := make([]byte, 4)
	lenBytes[0] = byte(msgLen >> 24)
	lenBytes[1] = byte(msgLen >> 16)
	lenBytes[2] = byte(msgLen >> 8)
	lenBytes[3] = byte(msgLen)
	
	// Set write deadline to prevent hanging
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	
	// Write length prefix first
	_, err = c.conn.Write(lenBytes)
	if err != nil {
		c.Disconnect() // Connection might be broken, so disconnect
		return nil, errors.IPCError(fmt.Sprintf("failed to send message length: %v", err))
	}
	
	// Write message body
	_, err = c.conn.Write(reqData)
	if err != nil {
		c.Disconnect() // Connection might be broken, so disconnect
		return nil, errors.IPCError(fmt.Sprintf("failed to send request body: %v", err))
	}
	
	// Set read deadline
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	// Read response length (4 bytes)
	respLenBytes := make([]byte, 4)
	_, err = io.ReadFull(c.conn, respLenBytes)
	if err != nil {
		c.Disconnect()
		return nil, errors.IPCError(fmt.Sprintf("failed to read response length: %v", err))
	}
	
	// Parse response length
	respLen := int(respLenBytes[0])<<24 | int(respLenBytes[1])<<16 | int(respLenBytes[2])<<8 | int(respLenBytes[3])
	
	// Sanity check on response length to prevent DoS
	if respLen <= 0 || respLen > 1024*1024 { // Max 1MB response
		c.Disconnect()
		return nil, errors.IPCError(fmt.Sprintf("invalid response length: %d", respLen))
	}
	
	// Read the exact response size
	respData := make([]byte, respLen)
	_, err = io.ReadFull(c.conn, respData)
	if err != nil {
		c.Disconnect()
		return nil, errors.IPCError(fmt.Sprintf("failed to read response body: %v", err))
	}
	
	// Clear read deadline
	c.conn.SetReadDeadline(time.Time{})
	
	// Unmarshal the response
	var resp OperationResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, errors.IPCError(fmt.Sprintf("failed to unmarshal response: %v", err))
	}
	
	// Validate response
	if resp.Results == nil {
		resp.Results = make(map[string]string)
	}
	
	// Check timestamp to prevent replay attacks (if server included it)
	if timestamp, ok := resp.Results["timestamp"]; ok {
		responseTime, err := strconv.ParseInt(timestamp, 10, 64)
		if err == nil {
			// Check if response is within 30 seconds
			timeDiff := time.Now().UnixNano() - responseTime
			if timeDiff < 0 || timeDiff > 30*int64(time.Second) {
				c.logger.Warnf("Response timestamp suspicious: diff=%v ns", timeDiff)
			}
		}
	}
	
	c.logger.Debugf("Received response for operation type %s: success=%v", req.Type, resp.Success)
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