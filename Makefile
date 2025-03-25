.PHONY: build clean install uninstall test test-auth test-passing test-race test-coverage test-verbose

# Project settings
BINARY_NAME := applock-go
HELPER_NAME := applock-helper
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /etc/applock-go
SYSTEMD_DIR := /etc/systemd/system
SERVICE_FILE := $(SYSTEMD_DIR)/$(BINARY_NAME).service
GO_FILES := $(shell find . -name '*.go')

# Directories
CMD_DIR := ./cmd/applock
HELPER_DIR := ./cmd/applock-helper

# Build settings
LDFLAGS := -ldflags="-s -w"
BUILD_FLAGS := -trimpath

all: build

# Build the application
build: $(GO_FILES)
	@echo "Building $(BINARY_NAME)..."
	@go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Building $(HELPER_NAME)..."
	@go build $(BUILD_FLAGS) $(LDFLAGS) -o $(HELPER_NAME) $(HELPER_DIR)
	@echo "Build complete!"

# Create a release build
release: $(GO_FILES)
	@echo "Creating release build..."
	@go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Building $(HELPER_NAME) release..."
	@go build $(BUILD_FLAGS) $(LDFLAGS) -o $(HELPER_NAME) $(HELPER_DIR)
	@echo "Release build complete!"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests only for the auth package
test-auth:
	@echo "Running auth package tests..."
	@go test -v applock-go/internal/auth

# Run only the passing tests
test-passing:
	@echo "Running only the passing tests..."
	@go test -v applock-go/internal/auth -run "TestAuthenticateZKP|TestAuthenticateZKP_MemoryClearing|TestAuthenticateZKP_Timeout|TestAuthenticateZKP_MaxIterations|TestClearMemory|TestBruteForceProtection|TestHashGeneration|TestUnsupportedHashAlgorithm"

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	@go test -v -race ./...

# Run tests with coverage reporting
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p test-reports
	@go test -v -coverprofile=test-reports/coverage.out ./...
	@go tool cover -html=test-reports/coverage.out -o test-reports/coverage.html
	@echo "Coverage report generated at test-reports/coverage.html"
	@go tool cover -func=test-reports/coverage.out

# Run tests with verbose output and coverage
test-verbose:
	@echo "Running tests with verbose output and coverage..."
	@mkdir -p test-reports
	@go test -v -race -coverprofile=test-reports/coverage.out ./...
	@go tool cover -html=test-reports/coverage.out -o test-reports/coverage.html
	@echo "Coverage report generated at test-reports/coverage.html"
	@go tool cover -func=test-reports/coverage.out

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@rm -f $(HELPER_NAME)
	@go clean
	@echo "Clean complete!"

# Install the application
install-bin: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo install -d $(DESTDIR)$(INSTALL_DIR)
	@sudo install -m 755 $(BINARY_NAME) $(DESTDIR)$(INSTALL_DIR)/$(BINARY_NAME)
	@sudo install -m 4755 $(HELPER_NAME) $(DESTDIR)$(INSTALL_DIR)/$(HELPER_NAME)
	@sudo install -d $(DESTDIR)$(CONFIG_DIR)
	@if [ ! -f $(DESTDIR)$(CONFIG_DIR)/config.toml ]; then \
		echo "Creating default configuration..."; \
		sudo mkdir -p $(DESTDIR)$(CONFIG_DIR); \
		sudo ./$(BINARY_NAME) create-config $(DESTDIR)$(CONFIG_DIR)/config.toml; \
	else \
		echo "Configuration file already exists, not overwriting"; \
	fi
	@echo "Installation complete!"

# Uninstall the application
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f $(DESTDIR)$(INSTALL_DIR)/$(BINARY_NAME)
	@sudo rm -f $(DESTDIR)$(INSTALL_DIR)/$(HELPER_NAME)
	@sudo rm -f $(DESTDIR)$(CONFIG_DIR)/config.toml
	@echo "Note: Configuration directory $(CONFIG_DIR) was removed"
	@sudo systemctl disable --now $(BINARY_NAME).service && sudo rm $(SERVICE_FILE)
	@echo "Uninstall complete!"

# Create and install systemd service file
install-service:
	@echo "Installing systemd service..."
	@sudo install -d $(DESTDIR)$(SYSTEMD_DIR)
	@sudo install -m 644 docs/$(BINARY_NAME).service $(DESTDIR)$(SERVICE_FILE)
	@echo "Service installation complete!"
	@echo "To enable the service, run: sudo systemctl enable --now $(BINARY_NAME).service"

# Full installation including systemd service
install: install-bin install-service
	@echo "Full installation complete!"
	@echo "To set up the authentication secret: sudo $(BINARY_NAME) set-secret"

# Run application (as root)
run:
	@echo "Running $(BINARY_NAME)..."
	@if [ "$$(id -u)" -ne 0 ]; then install-service\
		echo "This application requires root privileges to run"; \
		sudo ./$(BINARY_NAME); \
	else \
		./$(BINARY_NAME); \
	fi
