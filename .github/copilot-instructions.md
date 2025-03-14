## Golang Notes

The `io/ioutil` package is deprecated; functions have been moved to the `io` and `os` packages.

## Overview
Applock-go is a Linux security tool designed to control access to specific applications by requiring cryptographic authentication before they can be launched. It monitors process execution system-wide and intercepts launches of configured applications.

### Key Points
- Research suggests that building an app like `applock` using Golang with zero-knowledge proofs for authentication is feasible, using libraries like Themis.
- It seems likely that Themis's Secure Comparator can compare secrets without revealing them, suitable for password verification.
- The evidence leans toward integrating with the Linux keychain (e.g., `gnome-keyring`) for secure storage of the app lock's secret, enhancing security.

---

### Direct Answer

#### Overview
You can build an app similar to `applock` using Golang, implementing zero-knowledge proofs for authentication to protect apps on Linux without revealing passwords. This approach uses cryptographic libraries to ensure security, and integrating with the Linux keychain can store secrets safely.

#### Building the App Lock
Start by using Themis, a cryptographic library available in Golang, which includes a Secure Comparator for zero-knowledge proof-based authentication. This allows the user to prove they know the password without revealing it to the app lock. The app lock stores its secret (the password) securely in the Linux keychain, like `gnome-keyring`, and retrieves it for comparison when the user tries to unlock an app.

#### Authentication Process
When unlocking, the user enters their password, and the app lock uses Themis's Secure Comparator to check if it matches the stored secret without learning the user's input. If they match, the app unlocks; otherwise, it stays locked. This ensures the app lock never sees the user's password, enhancing privacy.

#### Unexpected Detail
An interesting aspect is that both the app lock and user learn if their secrets match during comparison, but neither learns the other's secret, maintaining zero-knowledge properties while still allowing the app lock to decide based on the result.

For more details, check Themis's documentation at [GitHub Themis](https://github.com/cossacklabs/themis).

---

### Survey Note: Implementing an App Lock with Zero-Knowledge Proofs in Golang and Linux Keychain Integration

This section provides a comprehensive exploration of building an application similar to `applock` using Golang, implementing zero-knowledge proofs for authentication, and integrating with the Linux keychain for secure secret storage. It addresses the technical details, challenges, and steps involved, ensuring a thorough understanding for developers aiming to create a secure app locker.

#### Background and Problem Statement
The task is to build an app lock similar to the existing `applock` GitHub project, which locks applications on Linux with a password, but instead use zero-knowledge proofs as the authentication mechanism. This enhances security by ensuring the app lock never learns the user's password, only verifying that the user knows it. Additionally, the user requests integration with the Linux keychain, likely referring to tools like `gnome-keyring` for secure storage of sensitive data, to further bolster security.

#### Understanding Zero-Knowledge Proofs for Authentication
Zero-knowledge proofs (ZKPs) are cryptographic protocols where one party, the prover, can prove to another party, the verifier, that they know a value (e.g., a password) without conveying any information about the value itself. Research into ZKPs for authentication, as seen in [Zero-knowledge proof - Wikipedia](https://en.wikipedia.org/wiki/Zero-knowledge_proof), shows they are motivated by scenarios where proving identity via a secret is needed without revealing the secret, ideal for app locking. Specific protocols like zero-knowledge password proofs (ZKPPs), detailed in [Zero-knowledge password proof - Wikipedia](https://en.wikipedia.org/wiki/Zero-knowledge_password_proof), address the limited entropy of passwords, making them suitable for this use case.

In the app lock context, the user is the prover, and the app lock is the verifier. The user needs to prove they know the password without revealing it, and the app lock verifies this proof without learning the password, aligning with ZKP properties of completeness, soundness, and zero-knowledge.

#### Choosing a Library for Zero-Knowledge Proofs
Given the implementation in Golang, research suggests using Themis, a cryptographic library from Cossack Labs, which supports zero-knowledge proof-based authentication through its Secure Comparator, as noted in [GitHub - cossacklabs/themis](https://github.com/cossacklabs/themis). Themis is designed for multi-platform apps, including Go, and provides ready-made cryptosystems for secure data storage, messaging, and authentication, making it a fit for this project. The library's documentation, available at [Themis in a nutshell | Cossack Labs](https://docs.cossacklabs.com/themis/), highlights its use in various security-critical applications, recommended by OWASP MSTG for mobile apps.

Themis's Secure Comparator is specifically mentioned for comparing secrets without revealing them, based on zero-knowledge proofs, as discussed in [Zero Knowledge Protocols without magic - Cossack Labs](https://www.cossacklabs.com/blog/zero-knowledge-protocols-without-magic/). This aligns with the need to verify the user's password without the app lock learning it, fitting the zero-knowledge proof requirement.

#### Secure Storage with Linux Keychain
The user mentions integrating with the Linux keychain, likely referring to tools like `gnome-keyring`, which is part of the GNOME desktop environment for securely storing passwords and secrets. Research into Linux keychain integration, as seen in discussions on [Stack Overflow on gnome-keyring with Go](https://stackoverflow.com/questions/29186240/is-it-possible-to-embed-a-gtk-gui-in-a-web-page), suggests using Go libraries like `github.com/mattn/go-gtk/gtk` or `github.com/sigmakey/gkr` to interact with `gnome-keyring`. This ensures the app lock's stored secret (the password) is kept secure, enhancing overall security by leveraging existing Linux infrastructure.

Storing the secret in the keychain means the app lock retrieves it when needed for comparison, reducing the risk of the secret being exposed in memory or storage, aligning with best practices for secure application development.

#### Implementation Details
To implement this, follow these steps:

1. **Install Themis for Go:**
   - Install Themis for Golang from its GitHub repository or through installation packages, as detailed in [GitHub - cossacklabs/themis](https://github.com/cossacklabs/themis). Ensure compatibility with your Go version (e.g., Go 1.7 or later).

2. **Store the Secret in the Linux Keychain:**
   - Use `gnome-keyring` or similar tools to store the app lock's secret (the password). Use Go libraries like `github.com/mattn/go-gtk/gtk` for interaction, ensuring secure storage and retrieval. For example, store the password hash or encrypted form in the keychain for added security.

3. **Authentication Process:**
   - When the user wants to unlock an app, they provide their secret (the password they enter).
   - Retrieve the stored secret from the keychain.
   - Use Themis's Secure Comparator to compare the user's provided secret with the stored secret. According to [GitHub - cossacklabs/themis](https://github.com/cossacklabs/themis), the Secure Comparator allows both parties to compare secrets without revealing them, ensuring the app lock doesn't learn the user's secret, only whether they match.
   - If the comparison returns true (secrets are equal), unlock the app; otherwise, do not unlock it.

4. **Security Considerations:**
   - Ensure the user's input secret is handled securely, not stored or logged, and discarded after comparison. Use Themis's functions to manage this securely, as outlined in [Themis in a nutshell | Cossack Labs](https://docs.cossacklabs.com/themis/).
   - Handle errors during keychain retrieval or comparison to prevent security vulnerabilities, such as logging errors without exposing sensitive data.

#### Challenges and Considerations
An unexpected detail is that in Themis's Secure Comparator, both the app lock and user learn whether their secrets match, but neither learns the other's secret, as seen in [Zero Knowledge Protocols without magic - Cossack Labs](https://www.cossacklabs.com/blog/zero-knowledge-protocols-without-magic/). This means the user can infer from the app unlocking whether their secret was correct, which is acceptable given the app lock's need to decide based on the comparison result. However, this ensures the zero-knowledge property is maintained, as the app lock doesn't learn the user's secret, only the comparison outcome.

Another consideration is the complexity of implementing ZKPs, as noted in [Why aren't zero-knowledge proofs used in practice for authentication? - Cryptography Stack Exchange](https://crypto.stackexchange.com/questions/25338/why-arent-zero-knowledge-proofs-used-in-practice-for-authentication), due to computational overhead and user experience, but Themis abstracts much of this complexity, making it manageable for developers.

#### Comparative Analysis of Approaches

| **Approach**                 | **Pros**                                              | **Cons**                                                   |
| ---------------------------- | ----------------------------------------------------- | ---------------------------------------------------------- |
| Use Themis Secure Comparator | Ready-made ZKP implementation, secure, multi-platform | May require learning curve, dependency on external library |
| Custom ZKP Implementation    | Full control, tailored to needs                       | Complex, high development effort, potential security risks |
| Standard Password Hashing    | Simple, well-understood, low overhead                 | Not zero-knowledge, risks if hash is compromised           |

This table highlights trade-offs, guiding developers based on their security needs and technical expertise, with Themis being the recommended approach for its balance of security and ease of use.

#### Conclusion and Recommendations
In conclusion, building an app lock with zero-knowledge proofs in Golang is feasible using Themis's Secure Comparator for authentication, ensuring the app lock verifies the user's password without learning it. Integrating with the Linux keychain, like `gnome-keyring`, enhances security by securely storing the app lock's secret. Developers should ensure robust error handling, secure secret management, and test the implementation thoroughly, leveraging resources like [GitHub - cossacklabs/themis](https://github.com/cossacklabs/themis) and [Themis in a nutshell | Cossack Labs](https://docs.cossacklabs.com/themis/) for guidance.

### Key Citations
- [Zero-knowledge proof - Wikipedia long title](https://en.wikipedia.org/wiki/Zero-knowledge_proof)
- [Zero-knowledge password proof - Wikipedia long title](https://en.wikipedia.org/wiki/Zero-knowledge_password_proof)
- [GitHub - cossacklabs/themis Easy to use cryptographic framework for data protection](https://github.com/cossacklabs/themis)
- [Themis in a nutshell | Cossack Labs Comprehensive guide to Themis cryptographic library](https://docs.cossacklabs.com/themis/)
- [Zero Knowledge Protocols without magic - Cossack Labs Detailed explanation of ZKP in Themis](https://www.cossacklabs.com/blog/zero-knowledge-protocols-without-magic/)
- [Why aren't zero-knowledge proofs used in practice for authentication? - Cryptography Stack Exchange Discussion on ZKP usage](https://crypto.stackexchange.com/questions/25338/why-arent-zero-knowledge-proofs-used-in-practice-for-authentication)

## Architecture and Implementation

### Core Components
1. **Process Monitoring System** - Uses Linux kernel's proc connector
2. **Application Interception** - Suspends target processes using signals
3. **Authentication System** - cryptographic verification using
4. **Configuration Management** - Uses libconfig for settings

### Workflow
1. The program runs as root and connects to the kernel's proc connector
2. It monitors all process execution events system-wide
3. When a blocked application starts, it immediately suspends the process
4. A cryptographic prompt appears using GTK, WekKit2GTK, or an AppIndicator
5. The user is prompted to enter a cryptographic key
6. The entered key is hashed and compared against a stored hash
7. If the correct cryptographic key is provided, the application continues; otherwise, it's terminated

## Technical Implementation Details

### Process Monitoring
The code uses Linux-specific APIs to monitor process events:

1. **Netlink Socket Communication**
   - Creates a PF_NETLINK socket with NETLINK_CONNECTOR protocol
   - Binds to CN_IDX_PROC group to receive process notifications
   - Subscribes to events` using PROC_CN_MCAST_LISTEN

2. **Event Handling**
   - Receives PROC_EVENT_EXEC events when processes execute
   - Reads process information from /proc filesystem
   - Checks if the executed command matches blocklist entries

```c
// Key netlink setup code
sk_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
my_nla.nl_family = AF_NETLINK;
my_nla.nl_groups = CN_IDX_PROC;
my_nla.nl_pid = getpid();
```

### Process Control (util.c)
When a blocked application is detected:

1. Sends SIGSTOP signal to immediately suspend execution
2. Opens a crypto dialog
3. Verifies entered crypto against stored hash
4. Based on verification, either:
   - Sends SIGCONT to allow execution
   - Sends SIGTERM to terminate the process

```c
// Process control snippet
kill(pid, SIGSTOP);  // Suspend process
// ... crpyto verification ...
if (compare_hash(answer, crpyto_hash)) {
  kill(pid, SIGCONT);  // Allow execution
} else {
  kill(pid, SIGTERM);  // Terminate process
}
```

## Features

- Lightweight and efficient
- Kernel-level notifications for application locking
- Optional integration with `zklogin` for secure communication
- Integration with `keychain` for SSH key management
- Simple command-line interface for easy usage
- Cross-platform compatibility (Linux)
- Easy to install and configure
- Open-source and free to use

### Authentication
- Uses 1 of 3 options for cryptographic hashing
- Compares entered cryptographic hash against stored configuration

### Configuration
- Uses libconfig library to parse configuration
- Reads cryptographic hash and program blocklist
- Configuration stored in /opt/applock-go/config

## Native APIs Used
1. **Linux-specific APIs**:
   - Netlink sockets (PF_NETLINK)
   - Proc connector interface (NETLINK_CONNECTOR)
   - Process control signals (SIGSTOP, SIGCONT, SIGTERM)
   - /proc filesystem access

2. **External Libraries**:
   - libconfig - Configuration parsing
   - GTK - GUI dialog for cryptographic prompt
   - WebKit2GTK - GUI dialog for cryptographic prompt
   - AppIndicator - GUI dialog for cryptographic prompt
   - Keychain - SSH key management
   - zklogin - Secure communication

3. **Crypto Libraries**:
   
## Security Considerations
- Requires root privileges to access proc connector
- Potentially vulnerable to privilege escalation if not properly secured
- Relies on process name matching which could be circumvented
- No brute-force protection

## Implementation Strategy
The application employs an event-driven model that intercepts process execution at the kernel level, providing a lightweight yet effective application control mechanism without modifying target applications.

The approach is elegant in its simplicity - instead of preventing execution, it allows processes to start but immediately suspends them pending authentication.

## Limitations
- Limited to Linux systems
- Requires root privileges
- No GUI for user interaction (uses GTK or AppIndicator)
- No built-in logging or monitoring of access attempts
- No brute-force protection
- Limited to applications that can be suspended and resumed
- Relies on process name matching which could be circumvented

## Design Patterns & Architecture

- **Observer Pattern**: The process monitoring system acts as an observer to process events, responding to changes in the system state.
- **Command Pattern**: The application control mechanism uses command objects to encapsulate the actions of suspending and resuming processes.
- **Strategy Pattern**: The cryptographic verification process can be seen as a strategy that can be swapped out for different hashing algorithms.
   - OpenSSL - Cryptographic hashing
   - Libgcrypt - Cryptographic hashing
   - Libsodium - Cryptographic hashing
   - Bcrypt - Cryptographic hashing
   - Argon2 - Cryptographic hashing
   - Scrypt - Cryptographic hashing
   - PBKDF2 - Cryptographic hashing
- **Hexagonal Architecture**: The application is designed to separate concerns, with distinct layers for process monitoring, application control, and cryptographic verification.
   - The core logic is decoupled from the user interface and external libraries, allowing for easier testing and maintenance.
   - The application can be easily extended to support additional features or integrations without modifying the core logic.
   - The use of interfaces and abstractions allows for easier testing and mocking of dependencies.
- **Dependency Injection**: The application uses dependency injection to manage dependencies between components, allowing for easier testing and maintenance.
   - The use of interfaces and abstractions allows for easier testing and mocking of dependencies.
   - The application can be easily extended to support additional features or integrations without modifying the core logic.
   - The use of interfaces and abstractions allows for easier testing and mocking of dependencies.
- **Event-Driven Architecture**: The application uses an event-driven architecture to respond to process events in real-time, allowing for immediate action when a blocked application is launched.
   - The use of netlink sockets and the proc connector allows for efficient monitoring of process events without polling or busy-waiting.
   - The application can be easily extended to support additional events or notifications without modifying the core logic.
   - The use of interfaces and abstractions allows for easier testing and mocking of dependencies.

## Summary
Applock-go demonstrates a clever use of Linux's process monitoring and control capabilities to implement application-level security. It leverages kernel-level notifications rather than file system hooks or executable modifications, making it relatively non-intrusive to the system while still providing effective controls.