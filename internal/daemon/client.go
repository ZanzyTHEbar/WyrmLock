package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"applock-go/internal/auth"
	"applock-go/internal/config"
	"applock-go/internal/gui"
	"applock-go/internal/ipc"
	"applock-go/internal/logging"
	"applock-go/internal/monitor"
	"applock-go/internal/util"
)

// Client represents a connection to the daemon
type Client struct {
	config          *config.Config
	authenticator   *auth.Authenticator
	gui             *gui.GUI
	conn            net.Conn
	encoder         *json.Encoder
	decoder         *json.Decoder
	logger          *logging.Logger
	stopCh          chan struct{}
	mu              sync.Mutex
	shutdownHandler *util.ShutdownHandler
}

// NewClient creates a new client instance
func NewClient(config *config.Config, authenticator *auth.Authenticator) (*Client, error) {
	logger := logging.DefaultLogger
	if logger == nil {
		logger = logging.NewLogger("[client]", config.Verbose)
	}

	gui, err := gui.NewGUI(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create GUI: %v", err)
	}

	return &Client{
		config:        config,
		authenticator: authenticator,
		gui:           gui,
		logger:        logger,
		stopCh:        make(chan struct{}),
	}, nil
}

// Connect establishes a connection to the daemon
func (c *Client) Connect() error {
	conn, err := net.Dial("unix", c.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %v", err)
	}

	c.conn = conn
	c.encoder = json.NewEncoder(conn)
	c.decoder = json.NewDecoder(conn)

	go c.handleMessages()

	return nil
}

// Disconnect closes the connection to the daemon
func (c *Client) Disconnect() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// handleMessages processes incoming messages from the daemon
func (c *Client) handleMessages() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
			var msg ipc.Message
			if err := c.decoder.Decode(&msg); err != nil {
				c.logger.Debugf("Error reading message: %v", err)
				return
			}

			switch msg.Type {
			case ipc.MsgProcessEvent:
				c.handleProcessEvent(msg)
			case ipc.MsgAuthRequest:
				c.handleAuthRequest(msg)
			case ipc.MsgPing:
				c.encoder.Encode(ipc.Message{Type: ipc.MsgPong})
			}
		}
	}
}

// handleProcessEvent processes a process event message
func (c *Client) handleProcessEvent(msg ipc.Message) {
	if msg.Process == nil {
		c.logger.Error("Received process event with nil process info")
		return
	}

	c.gui.ShowAuthDialog(msg.Process.Command, func(password string) {
		c.sendAuthResponse(msg.Process.PID, password)
	})
}

// handleAuthRequest processes an authentication request
func (c *Client) handleAuthRequest(msg ipc.Message) {
	if msg.Process == nil {
		c.logger.Error("Received auth request with nil process info")
		return
	}

	c.gui.ShowAuthDialog(msg.Process.Command, func(password string) {
		c.sendAuthResponse(msg.Process.PID, password)
	})
}

// sendAuthResponse sends an authentication response to the daemon
func (c *Client) sendAuthResponse(pid int, password string) {
	msg := ipc.Message{
		Type:     ipc.MsgAuthResponse,
		Password: password,
		Process: &monitor.ProcessInfo{
			PID:     pid,
			Command: "", // We don't need to send this back
		},
	}
	if err := c.encoder.Encode(msg); err != nil {
		c.logger.Errorf("Failed to send auth response: %v", err)
	}
}

// sendMessage sends a message to the daemon
func (c *Client) sendMessage(msg ipc.Message) error {
	return c.encoder.Encode(msg)
}

// Ping sends a ping message to the daemon and waits for a pong response
func (c *Client) Ping() (bool, error) {
	err := c.sendMessage(ipc.Message{Type: ipc.MsgPing})
	if err != nil {
		return false, fmt.Errorf("failed to send ping: %w", err)
	}

	// Wait for pong response
	var response ipc.Message
	if err := c.decoder.Decode(&response); err != nil {
		return false, fmt.Errorf("failed to receive pong: %w", err)
	}

	return response.Type == ipc.MsgPong, nil
}

// Stop gracefully shuts down the client
func (c *Client) Stop() error {
	close(c.stopCh)

	if c.conn != nil {
		// Best effort to notify daemon, ignore errors
		_ = c.sendMessage(ipc.Message{Type: ipc.MsgShutdown})
		return c.Disconnect()
	}

	return nil
}
