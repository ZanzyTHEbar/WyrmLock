package gui

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// GtkDialogImpl is a GTK implementation of the dialog interface
type GtkDialogImpl struct {
	mu sync.Mutex
}

// NewGtkDialogImpl creates a new GTK dialog implementation
func NewGtkDialogImpl() (*GtkDialogImpl, error) {
	// Check if zenity is installed
	if _, err := exec.LookPath("zenity"); err != nil {
		return nil, fmt.Errorf("zenity command not found; please install zenity package: %w", err)
	}

	return &GtkDialogImpl{}, nil
}

// ShowAuthDialog shows an authentication dialog using zenity
func (g *GtkDialogImpl) ShowAuthDialog(appName string) (string, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Use zenity to display a password dialog
	title := fmt.Sprintf("Authentication Required - %s", appName)
	cmd := exec.Command("zenity",
		"--password",
		"--title", title,
		"--text", fmt.Sprintf("Enter password to unlock %s:", appName),
		"--width", "400",
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
