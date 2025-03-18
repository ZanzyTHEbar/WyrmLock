package cmd

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"applock-go/internal/config"
)

// Config editor model
type configModel struct {
	inputs      []textinput.Model
	focusIndex  int
	cfg         *config.Config
	err         error
	saved       bool
	showConfirm bool
	loading     bool
}

func initialConfigModel() configModel {
	inputs := make([]textinput.Model, 4)

	for i := range inputs {
		input := textinput.New()
		input.Cursor.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
		input.CharLimit = 100

		switch i {
		case 0:
			input.Placeholder = "Path to executable"
			input.Focus()
		case 1:
			input.Placeholder = "Display name (optional)"
		case 2:
			input.Placeholder = "Keychain service name"
		case 3:
			input.Placeholder = "Keychain account name"
		}

		inputs[i] = input
	}

	return configModel{
		inputs:     inputs,
		focusIndex: 0,
		loading:    true,
	}
}

func (m configModel) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		loadConfigCmd(configPath), // Load configuration on initialization
	)
}

func (m configModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case configMsg:
		// Handle loaded configuration
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.cfg = msg.config
			// Pre-fill inputs with keychain values if config is loaded
			if m.cfg != nil && m.cfg.KeychainService != "" {
				m.inputs[2].SetValue(m.cfg.KeychainService)
				m.inputs[3].SetValue(m.cfg.KeychainAccount)
			}
		}
		m.loading = false
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "tab", "shift+tab", "up", "down":
			// Cycle between inputs
			s := msg.String()
			if s == "up" || s == "shift+tab" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}

			if m.focusIndex < 0 {
				m.focusIndex = len(m.inputs) - 1
			} else if m.focusIndex >= len(m.inputs) {
				m.focusIndex = 0
			}

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i < len(m.inputs); i++ {
				if i == m.focusIndex {
					cmds[i] = m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}
			return m, tea.Batch(cmds...)

		case "enter":
			if m.showConfirm {
				// Actually save the configuration here
				if m.cfg == nil {
					m.cfg = &config.Config{}
				}

				// Update config with form values
				blockApp := config.BlockedApp{
					Path:        m.inputs[0].Value(),
					DisplayName: m.inputs[1].Value(),
				}
				
				// Only add the blocked app if path is not empty
				if blockApp.Path != "" {
					m.cfg.BlockedApps = append(m.cfg.BlockedApps, blockApp)
				}
				
				// Update keychain settings if provided
				if m.inputs[2].Value() != "" {
					m.cfg.KeychainService = m.inputs[2].Value()
				}
				if m.inputs[3].Value() != "" {
					m.cfg.KeychainAccount = m.inputs[3].Value()
				}

				// Save config to file
				if err := config.SaveConfig(m.cfg, configPath); err != nil {
					m.err = fmt.Errorf("failed to save configuration: %w", err)
					m.showConfirm = false
					return m, nil
				}
				
				m.saved = true
				return m, tea.Quit
			}
			m.showConfirm = true
			return m, nil
		}
	}

	// Handle input changes
	cmd := m.updateInputs(msg)
	return m, cmd
}

func (m *configModel) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return tea.Batch(cmds...)
}

func (m configModel) View() string {
	var screen string

	// Title
	screen += titleStyle.Render("Applock-Go Configuration") + "\n\n"

	// If there's an error, show it
	if m.err != nil {
		screen += statusErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n\n"
	}

	// If loading
	if m.loading {
		screen += "Loading configuration...\n\n"
		return screen
	}

	if m.saved {
		screen += statusOkStyle.Render("✓ Configuration saved successfully!") + "\n\n"
		screen += "Press any key to exit."
		return screen
	}

	if m.showConfirm {
		screen += "Are you sure you want to save these changes? (enter/esc)\n\n"
		screen += "Application path: " + m.inputs[0].Value() + "\n"
		screen += "Display name: " + m.inputs[1].Value() + "\n"
		screen += "Keychain service: " + m.inputs[2].Value() + "\n"
		screen += "Keychain account: " + m.inputs[3].Value() + "\n\n"
		screen += "Press Enter to confirm or Esc to cancel."
		return screen
	}

	// Form fields
	screen += "Add application to block:\n\n"
	for i, input := range m.inputs {
		var label string
		switch i {
		case 0:
			label = "Application path:"
		case 1:
			label = "Display name (optional):"
		case 2:
			label = "Keychain service:"
		case 3:
			label = "Keychain account:"
		}

		field := lipgloss.NewStyle().Width(20).Render(label)
		screen += fmt.Sprintf("%s %s\n", field, input.View())
		screen += "\n"
	}

	// Show current configuration if loaded successfully
	if m.cfg != nil && len(m.cfg.BlockedApps) > 0 {
		screen += "\nCurrently blocked applications:\n"
		for i, app := range m.cfg.BlockedApps {
			name := app.DisplayName
			if name == "" {
				name = app.Path
			}
			screen += fmt.Sprintf("%d. %s\n", i+1, name)
		}
	}

	screen += "\nPress Tab to switch fields, Enter to save, Esc to quit.\n"
	return screen
}

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage application configuration",
		Long:  `Edit the applock-go configuration through an interactive interface.`,
		Run: func(cmd *cobra.Command, args []string) {
			p := tea.NewProgram(initialConfigModel())
			if _, err := p.Run(); err != nil {
				fmt.Printf("Error running configuration editor: %v\n", err)
			}
		},
	}

	return cmd
}
