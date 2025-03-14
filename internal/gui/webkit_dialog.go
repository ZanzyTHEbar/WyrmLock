package gui

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// WebKitDialogImpl is a WebKit2GTK implementation of the dialog interface
type WebKitDialogImpl struct {
	mu sync.Mutex
}

// NewWebKitDialogImpl creates a new WebKit2GTK dialog implementation
func NewWebKitDialogImpl() (*WebKitDialogImpl, error) {
	// Check if yad is installed (common WebKit2GTK dialog tool)
	if _, err := exec.LookPath("yad"); err != nil {
		return nil, fmt.Errorf("yad command not found; please install yad package: %w", err)
	}

	return &WebKitDialogImpl{}, nil
}

// ShowAuthDialog shows an authentication dialog using yad with HTML form
func (w *WebKitDialogImpl) ShowAuthDialog(appName string) (string, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Create HTML form content
	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authentication Required</title>
  <style>
    body { font-family: sans-serif; padding: 20px; }
    .container { max-width: 400px; margin: 0 auto; }
    h2 { color: #333; }
    .form-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 5px; }
    input[type="password"] { width: 100%%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
    .app-name { font-weight: bold; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Authentication Required</h2>
    <p>Enter password to unlock <span class="app-name">%s</span>:</p>
    <form>
      <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" autofocus required>
      </div>
    </form>
  </div>
</body>
</html>`, appName)

	// Use yad to display a WebKit2GTK password dialog
	title := fmt.Sprintf("Authentication Required - %s", appName)
	cmd := exec.Command("yad",
		"--html",
		"--title", title,
		"--form",
		"--field=password:H", "",
		"--width=400",
		"--height=300",
		"--borders=10",
		"--text", htmlContent,
		"--button=Cancel:1",
		"--button=Unlock:0",
	)

	// Capture the output (password)
	output, err := cmd.Output()

	// Check if the user clicked Cancel
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return "", false, nil // User cancelled, not an error condition
	} else if err != nil {
		return "", false, fmt.Errorf("error showing authentication dialog: %w", err)
	}

	// Trim newlines and parse output
	// yad returns form values separated by | character
	passwordLine := strings.TrimSpace(string(output))
	password := strings.TrimSuffix(passwordLine, "|")

	return password, true, nil
}
