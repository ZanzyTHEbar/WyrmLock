package gui

import (
	"errors"
	"fmt"
	"sync"

	"applock-go/internal/logging"
)

// Common errors
var (
	ErrCancelled      = errors.New("authentication cancelled by user")
	ErrUnsupportedGUI = errors.New("unsupported GUI type")
)

// Manager manages GUI interactions for the application
type Manager struct {
	guiType string
	mu      sync.Mutex
	logger  *logging.Logger

	// Different GUI implementations
	gtkImpl       *GtkDialogImpl
	webkitImpl    *WebKitDialogImpl
	indicatorImpl *AppIndicatorImpl
}

// NewManager creates a new GUI manager
func NewManager(guiType string) (*Manager, error) {
	// Get logger
	logger := logging.DefaultLogger
	if logger == nil {
		// If the default logger isn't initialized, create a new one
		logger = logging.NewLogger("[gui]", true)
	}

	manager := &Manager{
		guiType: guiType,
		logger:  logger,
	}

	// Initialize the selected GUI implementation
	logger.Debugf("Initializing GUI type: %s", guiType)

	switch guiType {
	case "gtk":
		impl, err := NewGtkDialogImpl()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize GTK: %w", err)
		}
		manager.gtkImpl = impl
	case "webkit2gtk":
		impl, err := NewWebKitDialogImpl()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WebKit2GTK: %w", err)
		}
		manager.webkitImpl = impl
	case "indicator":
		impl, err := NewAppIndicatorImpl()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AppIndicator: %w", err)
		}
		manager.indicatorImpl = impl
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedGUI, guiType)
	}

	logger.Debug("GUI manager initialized successfully")
	return manager, nil
}

// ShowAuthDialog shows an authentication dialog for the specified application
// Returns the entered password, a boolean indicating if authentication was attempted,
// and an error if there was a problem
func (m *Manager) ShowAuthDialog(appName string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debugf("Showing authentication dialog for %s using %s implementation", appName, m.guiType)

	var password string
	var ok bool
	var err error

	switch m.guiType {
	case "gtk":
		password, ok, err = m.gtkImpl.ShowAuthDialog(appName)
	case "webkit2gtk":
		password, ok, err = m.webkitImpl.ShowAuthDialog(appName)
	case "indicator":
		password, ok, err = m.indicatorImpl.ShowAuthDialog(appName)
	default:
		return "", false, fmt.Errorf("%w: %s", ErrUnsupportedGUI, m.guiType)
	}

	if err != nil {
		m.logger.Errorf("Authentication dialog error: %v", err)
		return "", false, err
	}

	if !ok {
		m.logger.Debug("User cancelled authentication")
		return "", false, nil
	}

	m.logger.Debug("Authentication information received from dialog")
	return password, true, nil
}

// DialogImpl is the interface that all dialog implementations must satisfy
type DialogImpl interface {
	// ShowAuthDialog shows an authentication dialog
	// Returns the entered password, a boolean indicating if authentication was attempted, and an error
	ShowAuthDialog(appName string) (string, bool, error)
}
