.PHONY: build clean install uninstall test

# Project settings
BINARY_NAME := applock-go
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /etc/applock-go
SYSTEMD_DIR := /etc/systemd/system
SERVICE_FILE := $(SYSTEMD_DIR)/$(BINARY_NAME).service
GO_FILES := $(shell find . -name '*.go')

# Directories
CMD_DIR := ./cmd/applock

# Build settings
LDFLAGS := -ldflags="-s -w"
BUILD_FLAGS := -trimpath

all: build

# Build the application
build: $(GO_FILES)
	@echo "Building $(BINARY_NAME)..."
	@go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete!"

# Create a release build
release: $(GO_FILES)
	@echo "Creating release build..."
	@go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Release build complete!"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@go clean
	@echo "Clean complete!"

# Install the application
install-bin: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo install -d $(DESTDIR)$(INSTALL_DIR)
	@sudo install -m 755 $(BINARY_NAME) $(DESTDIR)$(INSTALL_DIR)/$(BINARY_NAME)
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
