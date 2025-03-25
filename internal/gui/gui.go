package gui

import (
	"applock-go/internal/config"
)

// GUI handles the graphical user interface for authentication
type GUI struct {
	config *config.Config
}

// NewGUI creates a new GUI instance
func NewGUI(config *config.Config) (*GUI, error) {
	return &GUI{
		config: config,
	}, nil
}

// ShowAuthDialog displays an authentication dialog for the given application
func (g *GUI) ShowAuthDialog(appName string, callback func(password string)) {
	// TODO: Implement actual GUI dialog
	// For now, just call the callback with an empty password
	callback("")
} 