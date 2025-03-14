# Applock-go

A Linux security tool designed to control access to specific applications by requiring cryptographic authentication before they can be launched. It monitors process execution system-wide and intercepts launches of configured applications.

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

## Requirements

- Linux operating system
- Root privileges (required for proc connector access)
- Go 1.17+ for building from source
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

The default configuration file is installed at `/etc/applock-go/config.yaml`. You can edit this file to configure which applications should be locked and how authentication should work.

Example configuration:

```yaml
blockedApps:
  - path: /usr/bin/firefox
    displayName: Firefox
  - path: /usr/bin/chromium
    displayName: Chromium

auth:
  useZeroKnowledgeProof: true
  guiType: gtk

keychainService: applock-go
keychainAccount: default
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