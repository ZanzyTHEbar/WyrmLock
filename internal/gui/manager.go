package gui

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"wyrmlock/internal/logging"
)

// Common errors
var (
	ErrCancelled      = errors.New("authentication cancelled by user")
	ErrUnsupportedGUI = errors.New("unsupported GUI type")
)

// GuiType represents the type of GUI implementation to use
type GuiType string

const (
	GuiTypeWebKit GuiType = "webkit"
	GuiTypeGTK    GuiType = "gtk"
)

// Manager manages GUI interactions for the application
type Manager struct {
	mu            sync.Mutex
	guiType       GuiType
	theme         DialogTheme
	webkitDialog  *WebKitDialogImpl
	gtkDialog     *GTKDialogImpl
	appIndicator  *AppIndicatorImpl
	isSystemDark  bool
	themeCallback func(DialogTheme)
	logger        *logging.Logger
}

// NewManager creates a new GUI manager
func NewManager(guiType GuiType) (*Manager, error) {
	// Get logger
	logger := logging.DefaultLogger
	if logger == nil {
		// If the default logger isn't initialized, create a new one
		logger = logging.NewLogger("[gui]", true)
	}

	m := &Manager{
		guiType: guiType,
		theme:   LightTheme,
		logger:  logger,
	}

	// Initialize dialog implementations
	var err error
	switch guiType {
	case GuiTypeWebKit:
		m.webkitDialog, err = NewWebKitDialogImpl()
		if err != nil {
			return nil, fmt.Errorf("failed to create WebKit dialog: %w", err)
		}
	case GuiTypeGTK:
		m.gtkDialog, err = NewGTKDialogImpl()
		if err != nil {
			return nil, fmt.Errorf("failed to create GTK dialog: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported GUI type: %s", guiType)
	}

	// Initialize app indicator
	m.appIndicator, err = NewAppIndicatorImpl()
	if err != nil {
		return nil, fmt.Errorf("failed to create app indicator: %w", err)
	}

	// Initialize theme
	m.detectSystemTheme()

	logger.Debug("GUI manager initialized successfully")
	return m, nil
}

// SetTheme sets the theme for all GUI components
func (m *Manager) SetTheme(theme DialogTheme) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.theme = theme

	// Update dialog implementations
	if m.webkitDialog != nil {
		m.webkitDialog.SetTheme(theme)
	}
	if m.gtkDialog != nil {
		m.gtkDialog.SetTheme(theme)
	}
	if m.appIndicator != nil {
		m.appIndicator.SetTheme(theme)
	}

	// Notify callback if registered
	if m.themeCallback != nil {
		m.themeCallback(theme)
	}
}

// OnThemeChange registers a callback for theme changes
func (m *Manager) OnThemeChange(callback func(DialogTheme)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.themeCallback = callback
}

// detectSystemTheme detects the system theme preference
func (m *Manager) detectSystemTheme() {
	// Check if running in a desktop environment
	desktop := os.Getenv("XDG_CURRENT_DESKTOP")
	if desktop == "" {
		return // No desktop environment detected
	}

	// Check for dark mode preference
	var isDark bool
	switch desktop {
	case "GNOME":
		// Check GNOME dark mode
		out, err := exec.Command("gsettings", "get", "org.gnome.desktop.interface", "color-scheme").Output()
		if err == nil && strings.Contains(string(out), "dark") {
			isDark = true
		}
	case "KDE":
		// Check KDE dark mode
		out, err := exec.Command("kreadconfig5", "--group", "General", "--key", "ColorScheme").Output()
		if err == nil && strings.Contains(string(out), "Dark") {
			isDark = true
		}
	}

	// Update theme if dark mode is detected
	if isDark != m.isSystemDark {
		m.isSystemDark = isDark
		if isDark {
			m.SetTheme(DarkTheme)
		} else {
			m.SetTheme(LightTheme)
		}
	}
}

// ShowAuthDialog shows an authentication dialog
func (m *Manager) ShowAuthDialog(appName string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var password string
	var ok bool
	var err error

	m.logger.Debugf("Showing auth dialog for app: %s", appName)

	switch m.guiType {
	case GuiTypeWebKit:
		if m.webkitDialog != nil {
			password, ok, err = m.webkitDialog.ShowAuthDialog(appName)
		}
	case GuiTypeGTK:
		if m.gtkDialog != nil {
			password, ok, err = m.gtkDialog.ShowAuthDialog(appName)
		}
	default:
		return "", false, fmt.Errorf("%w: %s", ErrUnsupportedGUI, m.guiType)
	}

	if err != nil {
		m.logger.Errorf("Failed to show auth dialog: %v", err)
		return "", false, fmt.Errorf("failed to show auth dialog: %w", err)
	}

	if !ok {
		m.logger.Debug("User cancelled auth dialog")
		return "", false, nil
	}

	m.logger.Debug("Auth dialog completed successfully")
	return password, true, nil
}

// ShowSystemTrayIcon shows the system tray icon
func (m *Manager) ShowSystemTrayIcon() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.appIndicator == nil {
		return fmt.Errorf("app indicator not initialized")
	}

	return m.appIndicator.Show()
}

// HideSystemTrayIcon hides the system tray icon
func (m *Manager) HideSystemTrayIcon() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.appIndicator == nil {
		return fmt.Errorf("app indicator not initialized")
	}

	return m.appIndicator.Hide()
}

// DialogImpl is the interface that all dialog implementations must satisfy
type DialogImpl interface {
	// ShowAuthDialog shows an authentication dialog
	// Returns the entered password, a boolean indicating if authentication was attempted, and an error
	ShowAuthDialog(appName string) (string, bool, error)
}
