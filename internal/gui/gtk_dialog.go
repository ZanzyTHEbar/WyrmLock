package gui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// GTKDialogImpl is a GTK implementation of the dialog interface
type GTKDialogImpl struct {
	mu    sync.Mutex
	theme DialogTheme
}

// NewGTKDialogImpl creates a new GTK dialog implementation
func NewGTKDialogImpl() (*GTKDialogImpl, error) {
	// Check if zenity is installed (common GTK dialog tool)
	if _, err := exec.LookPath("zenity"); err != nil {
		return nil, fmt.Errorf("zenity command not found; please install zenity package: %w", err)
	}

	return &GTKDialogImpl{
		theme: LightTheme, // Default to light theme
	}, nil
}

// SetTheme sets the dialog theme
func (g *GTKDialogImpl) SetTheme(theme DialogTheme) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.theme = theme
}

// ShowAuthDialog shows an authentication dialog using zenity
func (g *GTKDialogImpl) ShowAuthDialog(appName string) (string, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Create CSS for theming
	css := fmt.Sprintf(`
		window {
			background-color: %s;
			color: %s;
		}
		.auth-dialog {
			padding: 20px;
			border-radius: 8px;
			box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
		}
		.auth-dialog entry {
			background-color: %s;
			color: %s;
			border: 2px solid %s;
			border-radius: 4px;
			padding: 8px;
			margin: 8px 0;
		}
		.auth-dialog entry:focus {
			border-color: %s;
			box-shadow: 0 0 0 3px rgba(25, 118, 210, 0.2);
		}
		.auth-dialog button {
			background-color: %s;
			color: %s;
			border: none;
			border-radius: 4px;
			padding: 8px 16px;
			margin: 4px;
			font-weight: bold;
		}
		.auth-dialog button:hover {
			background-color: %sdd;
		}
		.auth-dialog .app-name {
			font-weight: bold;
			color: %s;
		}
	`, g.theme.Background, g.theme.OnBackground,
		g.theme.Surface, g.theme.OnSurface,
		g.theme.Secondary, g.theme.Primary,
		g.theme.Primary, g.theme.OnPrimary,
		g.theme.Primary, g.theme.Primary)

	// Create a temporary CSS file
	cssFile, err := os.CreateTemp("", "applock-gtk-*.css")
	if err != nil {
		return "", false, fmt.Errorf("failed to create temporary CSS file: %w", err)
	}
	defer os.Remove(cssFile.Name())

	if _, err := cssFile.WriteString(css); err != nil {
		return "", false, fmt.Errorf("failed to write CSS file: %w", err)
	}
	cssFile.Close()

	// Use zenity to display the GTK dialog
	cmd := exec.Command("zenity",
		"--password",
		"--title", fmt.Sprintf("Authentication Required - %s", appName),
		"--text", fmt.Sprintf("<span class='app-name'>%s</span>\nEnter password to unlock:", appName),
		"--width=400",
		"--height=200",
		"--class=auth-dialog",
		"--ok-label=Unlock",
		"--cancel-label=Cancel",
		fmt.Sprintf("--gtk-style=%s", cssFile.Name()),
	)

	// Capture the output
	output, err := cmd.Output()

	// Check if the user clicked Cancel
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return "", false, nil // User cancelled
	} else if err != nil {
		return "", false, fmt.Errorf("error showing authentication dialog: %w", err)
	}

	// Parse the output to get the password
	password := strings.TrimSpace(string(output))
	return password, true, nil
}
