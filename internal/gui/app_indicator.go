package gui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// AppIndicatorImpl is an implementation of the dialog interface using AppIndicator
type AppIndicatorImpl struct {
	mu             sync.Mutex
	notificationId int
}

// NewAppIndicatorImpl creates a new AppIndicator implementation
func NewAppIndicatorImpl() (*AppIndicatorImpl, error) {
	// Check if notify-send is available (used for notifications)
	if _, err := exec.LookPath("notify-send"); err != nil {
		return nil, fmt.Errorf("notify-send command not found; please install libnotify-bin package: %w", err)
	}

	// Check if kdialog is available (used for password entry)
	if _, err := exec.LookPath("kdialog"); err != nil {
		return nil, fmt.Errorf("kdialog command not found; please install kdialog package: %w", err)
	}

	return &AppIndicatorImpl{
		notificationId: 1,
	}, nil
}

// ShowAuthDialog shows an authentication dialog using AppIndicator
func (a *AppIndicatorImpl) ShowAuthDialog(appName string) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// First show a notification
	a.showNotification(appName)

	// Then show a password dialog
	title := fmt.Sprintf("Authentication Required - %s", appName)
	cmd := exec.Command("kdialog",
		"--password",
		fmt.Sprintf("Enter password to unlock %s:", appName),
		"--title", title,
	)

	// Capture the output (password)
	output, err := cmd.Output()

	// Check if the user clicked Cancel
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return "", false, nil // User cancelled, not an error condition
	} else if err != nil {
		return "", false, fmt.Errorf("error showing authentication dialog: %w", err)
	}

	// Trim newlines and return
	password := strings.TrimSpace(string(output))
	return password, true, nil
}

// showNotification shows a system notification
func (a *AppIndicatorImpl) showNotification(appName string) {
	// Create notification ID to replace previous notifications
	notificationId := fmt.Sprintf("applock-go-%d", a.notificationId)
	a.notificationId++

	// Try to find an appropriate lock icon
	iconPath := ""
	for _, path := range []string{
		"/usr/share/icons/gnome/48x48/status/locked.png",
		"/usr/share/icons/Adwaita/48x48/status/locked.png",
		"/usr/share/icons/oxygen/base/48x48/status/object-locked.png",
	} {
		if _, err := os.Stat(path); err == nil {
			iconPath = path
			break
		}
	}

	// If no icon was found, use a generic one
	if iconPath == "" {
		iconPath = "dialog-password"
	}

	// Show notification
	exec.Command("notify-send",
		"--app-name=Applock-go",
		"--icon="+iconPath,
		"--replace-id="+notificationId,
		"--urgency=critical",
		fmt.Sprintf("Authentication Required for %s", appName),
		"Enter your password to continue",
	).Run()

	// Sleep briefly to ensure notification is displayed before dialog
	time.Sleep(500 * time.Millisecond)
}
