package gui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// AppIndicatorImpl is a system tray implementation using AppIndicator
type AppIndicatorImpl struct {
	mu          sync.Mutex
	theme       DialogTheme
	assetsDir   string
	iconPath    string
	menuProcess *os.Process
}

// NewAppIndicatorImpl creates a new AppIndicator implementation
func NewAppIndicatorImpl() (*AppIndicatorImpl, error) {
	// Check if yad is installed (for menu display)
	if _, err := exec.LookPath("yad"); err != nil {
		return nil, fmt.Errorf("yad command not found; please install yad package: %w", err)
	}

	// Create assets directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	assetsDir := filepath.Join(homeDir, ".applock", "assets")
	if err := os.MkdirAll(assetsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create assets directory: %w", err)
	}

	// Create icon
	iconPath := filepath.Join(assetsDir, "applock.svg")
	if err := createIcon(iconPath); err != nil {
		return nil, fmt.Errorf("failed to create icon: %w", err)
	}

	return &AppIndicatorImpl{
		theme:     LightTheme,
		assetsDir: assetsDir,
		iconPath:  iconPath,
	}, nil
}

// SetTheme sets the dialog theme
func (a *AppIndicatorImpl) SetTheme(theme DialogTheme) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.theme = theme
}

// Show displays the system tray icon
func (a *AppIndicatorImpl) Show() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Create menu CSS
	css := fmt.Sprintf(`
		window {
			background-color: %s;
			color: %s;
		}
		menu {
			background-color: %s;
			color: %s;
			border: none;
			border-radius: 8px;
			padding: 8px 0;
			box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
		}
		menuitem {
			padding: 8px 16px;
			margin: 2px 8px;
			border-radius: 4px;
		}
		menuitem:hover {
			background-color: %s;
			color: %s;
		}
		menuitem:active {
			background-color: %sdd;
		}
		separator {
			background-color: %s;
			margin: 4px 8px;
		}
	`, a.theme.Background, a.theme.OnBackground,
		a.theme.Surface, a.theme.OnSurface,
		a.theme.Primary, a.theme.OnPrimary,
		a.theme.Primary, a.theme.Secondary)

	// Create CSS file
	cssPath := filepath.Join(a.assetsDir, "menu.css")
	if err := os.WriteFile(cssPath, []byte(css), 0600); err != nil {
		return fmt.Errorf("failed to write CSS file: %w", err)
	}

	// Create menu script
	menuScript := fmt.Sprintf(`#!/bin/sh
yad --notification \
	--image="%s" \
	--command="yad --menu \
		--title='AppLock Menu' \
		--width=200 \
		--height=300 \
		--no-buttons \
		--text='AppLock Menu' \
		--column='' \
		'Show Protected Apps' \
		'Add Application' \
		'Settings' \
		'About' \
		'Quit' \
		--gtk-style='%s'" \
	--menu="Show Protected Apps|Add Application|Settings|About|Quit"
`, a.iconPath, cssPath)

	// Save menu script
	scriptPath := filepath.Join(a.assetsDir, "menu.sh")
	if err := os.WriteFile(scriptPath, []byte(menuScript), 0700); err != nil {
		return fmt.Errorf("failed to write menu script: %w", err)
	}

	// Start menu process
	cmd := exec.Command(scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start menu process: %w", err)
	}

	a.menuProcess = cmd.Process
	return nil
}

// Hide removes the system tray icon
func (a *AppIndicatorImpl) Hide() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.menuProcess != nil {
		if err := a.menuProcess.Kill(); err != nil {
			return fmt.Errorf("failed to kill menu process: %w", err)
		}
		a.menuProcess = nil
	}

	return nil
}

// createIcon creates the AppLock icon SVG file
func createIcon(path string) error {
	// Modern lock icon in SVG format
	iconSVG := `<?xml version="1.0" encoding="UTF-8"?>
<svg width="256" height="256" version="1.1" viewBox="0 0 67.733 67.733" xmlns="http://www.w3.org/2000/svg">
 <g transform="translate(0 -229.27)">
  <g transform="matrix(.26458 0 0 .26458 0 229.27)">
   <path d="m128 0c-35.346 0-64 28.654-64 64v32h-24c-13.254 0-24 10.746-24 24v128c0 13.254 10.746 24 24 24h176c13.254 0 24-10.746 24-24v-128c0-13.254-10.746-24-24-24h-24v-32c0-35.346-28.654-64-64-64zm0 32c17.673 0 32 14.327 32 32v32h-64v-32c0-17.673 14.327-32 32-32zm0 112c13.254 0 24 10.746 24 24s-10.746 24-24 24-24-10.746-24-24 10.746-24 24-24z" fill="#1976d2"/>
  </g>
 </g>
</svg>`

	return os.WriteFile(path, []byte(iconSVG), 0600)
}
