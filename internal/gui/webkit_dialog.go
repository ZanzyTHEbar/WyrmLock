package gui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
)

// DialogTheme defines the color scheme for dialogs
type DialogTheme struct {
	Primary      string
	Secondary    string
	Background   string
	Surface      string
	Error        string
	OnPrimary    string
	OnSecondary  string
	OnBackground string
	OnSurface    string
	OnError      string
}

// Default themes
var (
	LightTheme = DialogTheme{
		Primary:      "#1976d2",
		Secondary:    "#424242",
		Background:   "#ffffff",
		Surface:      "#ffffff",
		Error:        "#d32f2f",
		OnPrimary:    "#ffffff",
		OnSecondary:  "#ffffff",
		OnBackground: "#000000",
		OnSurface:    "#000000",
		OnError:      "#ffffff",
	}

	DarkTheme = DialogTheme{
		Primary:      "#90caf9",
		Secondary:    "#b0bec5",
		Background:   "#121212",
		Surface:      "#1e1e1e",
		Error:        "#ef5350",
		OnPrimary:    "#000000",
		OnSecondary:  "#000000",
		OnBackground: "#ffffff",
		OnSurface:    "#ffffff",
		OnError:      "#000000",
	}
)

// WebKitDialogImpl is a WebKit2GTK implementation of the dialog interface
type WebKitDialogImpl struct {
	mu          sync.Mutex
	theme       DialogTheme
	assetsDir   string
	templateDir string
}

// NewWebKitDialogImpl creates a new WebKit2GTK dialog implementation
func NewWebKitDialogImpl() (*WebKitDialogImpl, error) {
	// Check if yad is installed (common WebKit2GTK dialog tool)
	if _, err := exec.LookPath("yad"); err != nil {
		return nil, fmt.Errorf("yad command not found; please install yad package: %w", err)
	}

	// Create assets directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	assetsDir := filepath.Join(homeDir, ".wyrmlock", "assets")
	templateDir := filepath.Join(assetsDir, "templates")

	// Create directories if they don't exist
	for _, dir := range []string{assetsDir, templateDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create dialog implementation
	impl := &WebKitDialogImpl{
		theme:       LightTheme, // Default to light theme
		assetsDir:   assetsDir,
		templateDir: templateDir,
	}

	// Initialize templates
	if err := impl.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("failed to initialize templates: %w", err)
	}

	return impl, nil
}

// SetTheme sets the dialog theme
func (w *WebKitDialogImpl) SetTheme(theme DialogTheme) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.theme = theme
}

// initializeTemplates creates the HTML templates
func (w *WebKitDialogImpl) initializeTemplates() error {
	authTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Required</title>
    <style>
        :root {
            --primary: {{.Theme.Primary}};
            --secondary: {{.Theme.Secondary}};
            --background: {{.Theme.Background}};
            --surface: {{.Theme.Surface}};
            --error: {{.Theme.Error}};
            --on-primary: {{.Theme.OnPrimary}};
            --on-secondary: {{.Theme.OnSecondary}};
            --on-background: {{.Theme.OnBackground}};
            --on-surface: {{.Theme.OnSurface}};
            --on-error: {{.Theme.OnError}};
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            background-color: var(--background);
            color: var(--on-background);
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background-color: var(--surface);
            color: var(--on-surface);
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        h2 {
            color: var(--primary);
            margin-bottom: 1rem;
            font-size: 1.5rem;
            font-weight: 600;
        }

        .app-info {
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .app-icon {
            width: 48px;
            height: 48px;
            border-radius: 8px;
            background-color: var(--primary);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .app-icon svg {
            width: 24px;
            height: 24px;
            fill: var(--on-primary);
        }

        .app-name {
            font-weight: 600;
            color: var(--on-surface);
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--on-surface);
            font-weight: 500;
        }

        .input-wrapper {
            position: relative;
        }

        input[type="password"] {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 2px solid var(--secondary);
            border-radius: 4px;
            font-size: 1rem;
            background-color: var(--surface);
            color: var(--on-surface);
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        input[type="password"]:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(25, 118, 210, 0.2);
        }

        .toggle-password {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: var(--secondary);
            padding: 0.25rem;
            display: flex;
            align-items: center;
        }

        .toggle-password:hover {
            color: var(--primary);
        }

        .toggle-password svg {
            width: 20px;
            height: 20px;
            fill: currentColor;
        }

        .error-message {
            color: var(--error);
            font-size: 0.875rem;
            margin-top: 0.5rem;
            display: none;
        }

        .error-message.visible {
            display: block;
        }

        .buttons {
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }

        button {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s, transform 0.1s;
        }

        button:active {
            transform: translateY(1px);
        }

        .btn-primary {
            background-color: var(--primary);
            color: var(--on-primary);
        }

        .btn-primary:hover {
            background-color: {{.Theme.Primary}}dd;
        }

        .btn-secondary {
            background-color: var(--secondary);
            color: var(--on-secondary);
        }

        .btn-secondary:hover {
            background-color: {{.Theme.Secondary}}dd;
        }

        /* Accessibility */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        /* Dark mode detection */
        @media (prefers-color-scheme: dark) {
            :root {
                --primary: {{.DarkTheme.Primary}};
                --secondary: {{.DarkTheme.Secondary}};
                --background: {{.DarkTheme.Background}};
                --surface: {{.DarkTheme.Surface}};
                --error: {{.DarkTheme.Error}};
                --on-primary: {{.DarkTheme.OnPrimary}};
                --on-secondary: {{.DarkTheme.OnSecondary}};
                --on-background: {{.DarkTheme.OnBackground}};
                --on-surface: {{.DarkTheme.OnSurface}};
                --on-error: {{.DarkTheme.OnError}};
            }
        }
    </style>
</head>
<body>
    <main class="container" role="main">
        <h2 id="dialog-title">Authentication Required</h2>
        <div class="app-info">
            <div class="app-icon" role="img" aria-label="Application icon">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/>
                </svg>
            </div>
            <div>
                <p>Enter password to unlock:</p>
                <p class="app-name">{{.AppName}}</p>
            </div>
        </div>
        <form id="auth-form" aria-labelledby="dialog-title">
            <div class="form-group">
                <label for="password">Password:</label>
                <div class="input-wrapper">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           autocomplete="current-password"
                           aria-required="true"
                           aria-describedby="password-error"
                           required>
                    <button type="button" 
                            class="toggle-password" 
                            aria-label="Toggle password visibility">
                        <svg class="show-password" viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
                        </svg>
                        <svg class="hide-password" viewBox="0 0 24 24" aria-hidden="true" style="display: none;">
                            <path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>
                        </svg>
                    </button>
                </div>
                <div id="password-error" class="error-message" role="alert"></div>
            </div>
            <div class="buttons">
                <button type="button" class="btn-secondary" data-action="cancel">Cancel</button>
                <button type="submit" class="btn-primary">Unlock</button>
            </div>
        </form>
    </main>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('auth-form');
            const passwordInput = document.getElementById('password');
            const errorMessage = document.getElementById('password-error');
            const togglePassword = document.querySelector('.toggle-password');
            const showPasswordIcon = document.querySelector('.show-password');
            const hidePasswordIcon = document.querySelector('.hide-password');

            // Handle form submission
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                if (!passwordInput.value) {
                    showError('Please enter your password');
                    return;
                }
                // Submit the form
                form.submit();
            });

            // Handle password visibility toggle
            togglePassword.addEventListener('click', function() {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                showPasswordIcon.style.display = type === 'password' ? 'block' : 'none';
                hidePasswordIcon.style.display = type === 'password' ? 'none' : 'block';
            });

            // Handle cancel button
            document.querySelector('[data-action="cancel"]').addEventListener('click', function() {
                window.location.href = 'about:blank';
            });

            // Show error message
            function showError(message) {
                errorMessage.textContent = message;
                errorMessage.classList.add('visible');
                passwordInput.setAttribute('aria-invalid', 'true');
            }

            // Clear error on input
            passwordInput.addEventListener('input', function() {
                errorMessage.classList.remove('visible');
                passwordInput.removeAttribute('aria-invalid');
            });

            // Focus the password input
            passwordInput.focus();
        });
    </script>
</body>
</html>`

	// Save the template
	templatePath := filepath.Join(w.templateDir, "auth.html")
	return os.WriteFile(templatePath, []byte(authTemplate), 0600)
}

// ShowAuthDialog shows an authentication dialog using yad with HTML form
func (w *WebKitDialogImpl) ShowAuthDialog(appName string) (string, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Read the template
	templatePath := filepath.Join(w.templateDir, "auth.html")
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse template: %w", err)
	}

	// Create a temporary file for the rendered HTML
	tempDir := os.TempDir()
	htmlPath := filepath.Join(tempDir, "wyrmlock-auth.html")

	// Create the file
	htmlFile, err := os.Create(htmlPath)
	if err != nil {
		return "", false, fmt.Errorf("failed to create temporary HTML file: %w", err)
	}
	defer os.Remove(htmlPath) // Clean up the file when done

	// Render the template
	data := struct {
		AppName   string
		Theme     DialogTheme
		DarkTheme DialogTheme
	}{
		AppName:   appName,
		Theme:     w.theme,
		DarkTheme: DarkTheme,
	}

	if err := tmpl.Execute(htmlFile, data); err != nil {
		htmlFile.Close()
		return "", false, fmt.Errorf("failed to render template: %w", err)
	}
	htmlFile.Close()

	// Use yad to display the WebKit2GTK dialog
	cmd := exec.Command("yad",
		"--html",
		"--filename="+htmlPath,
		"--title", fmt.Sprintf("Authentication Required - %s", appName),
		"--width=400",
		"--height=500",
		"--center",
		"--fixed",
		"--no-buttons",
		"--no-markup",
		"--browser",
		"--print-uri",
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
	outputStr := strings.TrimSpace(string(output))
	if strings.HasPrefix(outputStr, "file://") {
		return "", false, nil // User closed the dialog
	}

	// The password will be in the form data
	password := strings.TrimSpace(outputStr)
	return password, true, nil
}
