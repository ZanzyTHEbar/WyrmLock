# Applock-go

A Linux security tool designed to control access to specific applications by requiring cryptographic authentication before they can be launched. It monitors process execution system-wide and intercepts launches of configured applications.

> [!WARNING]\
> This project is in early development and may not be fully functional. Use at your own risk.

## Features

- **Process Monitoring**: Uses Linux kernel's proc connector to monitor process execution events
- **Application Interception**: Suspends target processes using signals
- **Zero-Knowledge Authentication**: Uses Themis's Secure Comparator for zero-knowledge proof-based authentication
- **Multiple UI Options**: Supports GTK, WebKit2GTK, and AppIndicator interfaces
- **Secure Storage**: Integrates with the Linux keychain (e.g., gnome-keyring) for secure storage of secrets
- **Traditional Hashing**: Also supports traditional password hashing with bcrypt, argon2id, scrypt, and PBKDF2

## Security Features

- The app lock verifies the user's password without learning it, enhancing privacy
- Kernel-level monitoring ensures applications can't bypass the lock
- Integration with Linux keychain ensures secure storage of secrets
- Process suspension allows authentication before the application starts

## Feature Status Checklist

### Implemented Features

- [x] Command-line interface with multiple subcommands
- [x] Process monitoring via Linux proc connector
- [x] Configuration management
- [x] Multiple GUI dialog options (GTK, WebKit2GTK, AppIndicator)
- [x] Traditional password hashing (bcrypt, argon2id, scrypt, PBKDF2)
- [x] Support for both keychain and file-based secret storage
- [x] Process suspension and resumption
- [x] Configuration validation
- [x] Blocked application listing
- [x] Interactive configuration editor
- [x] Complete Zero-Knowledge Proof authentication via Themis
- [x] Comprehensive error handling and recovery
- [x] Proper signal handling for graceful termination
- [x] Brute force protection mechanisms

### To Be Implemented

- [ ] More granular access controls
- [ ] Enhanced logging and audit trails
- [ ] Child process tracking
- [ ] Application path verification (beyond name matching)
- [ ] Automated testing suite

### Future Work

- [ ] Biometric authentication integration
- [ ] Smart card/YubiKey support
- [ ] Graphical management interface
- [ ] Time-based access restrictions
- [ ] Usage pattern monitoring
- [ ] Library injection detection
- [ ] Detailed access logs and reporting
- [ ] User/group based permissions
- [ ] Integration with system notification services

## Requirements

- Linux operating system
- Root privileges (required for proc connector access)
- Go 1.23+ for building from source
- Themis library
- One of the following dialog libraries depending on your UI preference:
  - GTK: zenity
  - WebKit2GTK: yad
  - AppIndicator: notify-send and kdialog

## Installation

### From Source

1. Install dependencies:

```bash
# For Debian/Ubuntu
sudo apt-get install golang libthemis-dev zenity yad kdialog libnotify-bin

# For Fedora/RHEL
sudo dnf install golang themis-devel zenity yad kdialog libnotify
```

2. Clone the repository:

```bash
git clone https://applock-go-go.git
cd applock-go
```

3. Build and install:

```bash
sudo make install
```

4. Install systemd service (optional):

```bash
sudo make install-service
sudo systemctl enable --now applock-go.service
```

### Configuration

The default configuration file is installed at `/etc/applock-go/config.toml`. You can edit this file to configure which applications should be locked and how authentication should work.

Example configuration:

```toml
# Applock-go Configuration Example

# List of applications that should be locked
[[blockedApps]]
path = "/usr/bin/firefox"
displayName = "Firefox"

[[blockedApps]]
path = "/usr/bin/chromium"
displayName = "Chromium"

[[blockedApps]]
path = "/usr/bin/google-chrome"
displayName = "Google Chrome"

[[blockedApps]]
path = "/usr/bin/thunderbird"
displayName = "Thunderbird"

# Authentication settings
[auth]
# Whether to use zero-knowledge proof (Themis Secure Comparator)
# This enhances privacy by ensuring the app never learns your password
useZeroKnowledgeProof = true

# Path to store the secret if not using keychain
# Only used if keychainService/keychainAccount are not specified
secretPath = "/etc/applock-go/secret"

# Hash algorithm to use when not using ZKP
# Only used if useZeroKnowledgeProof is false
# Options: bcrypt, argon2id, scrypt, pbkdf2
hashAlgorithm = "argon2id"

# GUI type to use for authentication dialogs
# Options: gtk, webkit2gtk, indicator
guiType = "gtk"

# Keychain integration (Linux keyring)
# To use keychain integration, specify both service and account
keychainService = "applock-go"
keychainAccount = "default"

# Uncomment and set to true to enable verbose logging
# verbose = true
```

## Usage

Once installed and configured, Applock-go runs in the background and monitors process execution. When a configured application is launched, it will be suspended, and an authentication dialog will appear. The application will only continue if the correct authentication is provided.

### Setting a Secret

First time usage requires setting up a secret:

```bash
sudo applock-go -set-secret
```

## Architecture

Applock-go uses an event-driven architecture with the following components:

1. **Process Monitor**: Interfaces with the Linux kernel's proc connector to receive process events
2. **Authentication System**: Handles secure authentication using zero-knowledge proofs or traditional hashing
3. **GUI Manager**: Provides different dialog implementations for user interaction
4. **Configuration Management**: Handles loading and validation of application settings

## Building from Source

You will need to ensure that you have properly setup cossack labs' Themis library.

Please follow their development docs [Themis Documentation](https://docs.cossacklabs.com/themis/languages/go/installation/)

## Build Instructions

To build Applock-go, run the following command:

```bash
make build
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Cossack Labs for the Themis cryptographic library
- Inspired by the original C implementation of applock
