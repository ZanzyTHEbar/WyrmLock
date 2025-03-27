package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"wyrmlock/internal/logging"
	"wyrmlock/internal/privilege"
)

const (
	// HelperSocketPath is the path to the Unix domain socket for privileged operations
	HelperSocketPath = "/var/run/applock-helper.sock"
)

func main() {
	// Parse command-line flags
	daemonMode := flag.Bool("daemon", false, "Run in daemon mode")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	// Create logger
	logger := logging.NewLogger("[applock-helper]", *verbose)
	logger.Info("Starting applock-helper")

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Fatal("This program must be run as root")
		os.Exit(1)
	}

	// Create privilege manager
	privManager, err := privilege.NewPrivilegeManager(logger)
	if err != nil {
		logger.Fatalf("Failed to create privilege manager: %v", err)
		os.Exit(1)
	}

	// Start a verification loop to ensure we maintain required capabilities
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer cancel()

	privManager.StartVerificationLoop(ctx)

	// If daemon mode is enabled, run as a daemon
	if *daemonMode {
		runDaemon(logger, privManager)
		return
	}

	// Otherwise, run as a one-off command
	runCommand(logger, privManager)
}

// runDaemon runs the helper in daemon mode, listening for requests
func runDaemon(logger *logging.Logger, privManager *privilege.PrivilegeManager) {
	logger.Info("Running in daemon mode")

	// Remove existing socket if it exists
	if err := os.Remove(HelperSocketPath); err != nil && !os.IsNotExist(err) {
		logger.Fatalf("Failed to remove existing socket: %v", err)
		os.Exit(1)
	}

	// Create socket
	listener, err := net.Listen("unix", HelperSocketPath)
	if err != nil {
		logger.Fatalf("Failed to create socket: %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	// Set permissions so non-root can connect
	if err := os.Chmod(HelperSocketPath, 0660); err != nil {
		logger.Fatalf("Failed to set socket permissions: %v", err)
		os.Exit(1)
	}

	// Allow access from the applock group
	// TODO: In a real implementation, you'd verify the group exists first
	if err := os.Chown(HelperSocketPath, 0, 0); err != nil {
		logger.Fatalf("Failed to set socket ownership: %v", err)
		os.Exit(1)
	}

	logger.Infof("Listening on %s", HelperSocketPath)

	// Setup signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigCh
		logger.Infof("Received signal %v, shutting down", sig)
		listener.Close()
		os.Remove(HelperSocketPath)
		os.Exit(0)
	}()

	// Accept and handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("Failed to accept connection: %v", err)
			continue
		}

		// Handle connection in a goroutine
		go handleConnection(conn, logger, privManager)
	}
}

// handleConnection handles a client connection
func handleConnection(conn net.Conn, logger *logging.Logger, privManager *privilege.PrivilegeManager) {
	defer conn.Close()

	logger.Debug("New connection accepted")

	// Create decoder and encoder for JSON messages
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	// Create operation handler
	opHandler := privilege.NewOperationHandler(logger, privManager)
	if err := opHandler.InitializeHelper(); err != nil {
		logger.Errorf("Failed to initialize operation handler: %v", err)
		response := privilege.OperationResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to initialize operation handler: %v", err),
		}
		encoder.Encode(response)
		return
	}

	// Read and process requests
	for {
		var req privilege.OperationRequest
		if err := decoder.Decode(&req); err != nil {
			logger.Debugf("Connection closed: %v", err)
			return
		}

		logger.Debugf("Received request of type: %s", req.Type)

		// Execute the operation
		response, err := opHandler.ExecuteOperation(req)
		if err != nil {
			response = &privilege.OperationResponse{
				Success: false,
				Error:   err.Error(),
			}
		}

		// Send response
		if err := encoder.Encode(response); err != nil {
			logger.Errorf("Failed to send response: %v", err)
			return
		}
	}
}

// runCommand runs the helper as a one-off command
func runCommand(logger *logging.Logger, privManager *privilege.PrivilegeManager) {
	logger.Info("Running in command mode")

	// For now, just display capabilities
	if err := privManager.VerifyCapabilities(); err != nil {
		logger.Fatalf("Capability verification failed: %v", err)
		os.Exit(1)
	}

	// Just log that verification was successful
	logger.Info("All required capabilities verified")
} 