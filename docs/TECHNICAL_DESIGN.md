# Applock-go Technical Design Document

## Overview

Applock-go is a Linux security tool that controls access to specific applications by requiring cryptographic authentication before they can be launched. It monitors process execution system-wide and intercepts launches of configured applications, suspending them until proper authentication is provided.

## Security Architecture

### Core Security Principles

1. **Process-level Control**: Uses Linux kernel's proc connector to monitor and control process execution at the kernel level.
2. **Zero-Knowledge Authentication**: Implements zero-knowledge proofs using Themis's Secure Comparator to verify user passwords without learning them.
3. **Defense in Depth**: Provides multiple layers of security through kernel-level monitoring, process suspension, and cryptographic verification.
4. **Secure Storage**: Integrates with the Linux keychain (gnome-keyring) for secure storage of authentication secrets.

### Authentication Methods

Applock-go supports two authentication methods:

1. **Zero-Knowledge Proofs (Themis)**: 
   - Uses Themis's Secure Comparator for zero-knowledge proof-based authentication
   - Ensures the app never learns the user's password, only whether it matches
   - Provides highest level of security and privacy

2. **Traditional Password Hashing**:
   - Supports multiple algorithms: bcrypt, argon2id, scrypt, and PBKDF2
   - Implemented with strong security parameters for each algorithm
   - Provides compatibility with systems where Themis isn't available

## System Architecture

### Component Model

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│                │     │                │     │                │
│ Linux Kernel   │────▶│ Process        │────▶│ Authentication │
│ (proc events)  │     │ Monitor        │     │ System         │
│                │     │                │     │                │
└────────────────┘     └────────┬───────┘     └────────┬───────┘
                               │                       │
                               ▼                       ▼
                       ┌────────────────┐     ┌────────────────┐
                       │                │     │                │
                       │ Configuration  │     │ GUI            │
                       │ Management     │     │ Manager        │
                       │                │     │                │
                       └────────────────┘     └────────────────┘
```

### Key Components

1. **Process Monitor**:
   - Interfaces with Linux kernel's proc connector
   - Monitors all process execution events
   - Intercepts launches of configured applications

2. **Authentication System**:
   - Implements zero-knowledge proof authentication using Themis
   - Supports traditional password hashing algorithms
   - Integrates with Linux keychain for secure storage

3. **GUI Manager**:
   - Provides multiple user interface options (GTK, WebKit2GTK, AppIndicator)
   - Displays authentication dialogs when blocked applications are launched

4. **Configuration Management**:
   - Handles loading and validation of application settings
   - Maintains list of blocked applications and authentication parameters

## Implementation Details

### Process Monitoring

The process monitoring system uses the Linux kernel's proc connector to receive process events:

1. **Netlink Connection**:
   - Creates a PF_NETLINK socket with NETLINK_CONNECTOR protocol
   - Binds to CN_IDX_PROC group for process notifications
   - Subscribes to events using PROC_CN_MCAST_LISTEN

2. **Event Processing**:
   - Receives PROC_EVENT_EXEC events when processes are executed
   - Checks if the executable path matches any blocked applications
   - If matched, suspends the process and triggers authentication

### Process Control

When a blocked application is detected:

1. Immediately suspends the process using SIGSTOP
2. Shows an authentication dialog via the configured GUI system
3. Authenticates the user input against the stored secret
4. Based on authentication result:
   - If successful: Resumes the process with SIGCONT
   - If failed: Terminates the process with SIGTERM

### Authentication System

1. **Zero-Knowledge Authentication**:
   - Uses Themis's Secure Comparator for ZKP verification
   - Implements a multi-stage protocol where both client and server exchange messages
   - Ensures neither party learns the other's secret during comparison

2. **Traditional Password Verification**:
   - Implements secure verification for bcrypt, argon2id, scrypt, and PBKDF2
   - Uses constant-time comparison to prevent timing attacks
   - Enforces strong parameters for each algorithm

3. **Secret Management**:
   - Integrates with Linux keychain (e.g., gnome-keyring) for secure storage
   - Falls back to local file storage with secure permissions (0600)
   - Provides command-line tools for setting and managing secrets

### GUI System

The GUI system provides three different implementations:

1. **GTK Implementation**:
   - Uses zenity for simple, lightweight authentication dialogs
   - Provides password field with masked input

2. **WebKit2GTK Implementation**:
   - Uses yad with HTML content for more customizable dialogs
   - Supports theming and responsive layouts

3. **AppIndicator Implementation**:
   - Shows system notifications using notify-send
   - Uses kdialog for password entry
   - Integrates with desktop notification system

## Security Considerations

1. **Root Privileges**:
   - Requires root access for proc connector functionality
   - Uses principle of least privilege for file operations

2. **Potential Weaknesses**:
   - Process name matching could be circumvented by renamed executables
   - No protection against direct modifications to the kernel or process structures

3. **Operational Security**:
   - Secret files use secure permissions (0600) to prevent unauthorized access
   - Configuration validation prevents insecure settings

4. **Hardening Measures**:
   - Password attempts are isolated to individual application launches
   - Secure coding practices used throughout to prevent common vulnerabilities

## Design Patterns & Architecture

1. **Observer Pattern**: Process monitoring system observes kernel events
2. **Command Pattern**: Process control actions encapsulated as commands
3. **Strategy Pattern**: Authentication methods implemented as interchangeable strategies
4. **Hexagonal Architecture**: Core logic separated from external interfaces
5. **Dependency Injection**: Components receive dependencies through constructors
6. **Event-Driven Architecture**: System responds to process events in real-time

## Performance Considerations

1. **Memory Usage**:
   - Minimal memory footprint with efficient event handling
   - No persistent process tracking for non-blocked applications

2. **CPU Overhead**:
   - Event-driven design minimizes CPU usage during idle periods
   - Kernel-level notifications avoid the need for polling

3. **Latency**:
   - Authentication overhead only applied to configured applications
   - Process suspension happens immediately, minimizing potential for timing attacks

## Future Enhancements

1. **Enhanced Authentication**:
   - Biometric authentication integration
   - Smart card/YubiKey support

2. **Behavioral Analysis**:
   - Time-based access restrictions
   - Usage pattern monitoring

3. **Advanced Monitoring**:
   - Child process tracking
   - Library injection detection

4. **User Experience**:
   - Graphical configuration interface
   - Detailed access logs and reporting