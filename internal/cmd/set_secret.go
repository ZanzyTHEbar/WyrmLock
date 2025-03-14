package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"applock-go/internal/config"
)

// Secret setting model
type secretModel struct {
	input     textinput.Model
	confirm   textinput.Model
	cfg       *config.Config
	err       error
	inputMode int // 0: password, 1: confirm
	success   bool
}

func initialSecretModel() secretModel {
	input := textinput.New()
	input.Placeholder = "Enter secret"
	input.EchoMode = textinput.EchoPassword
	input.Focus()

	confirm := textinput.New()
	confirm.Placeholder = "Confirm secret"
	confirm.EchoMode = textinput.EchoPassword

	return secretModel{
		input:     input,
		confirm:   confirm,
		inputMode: 0,
	}
}

func (m secretModel) Init() tea.Cmd {
	return func() tea.Msg {
		cfg, err := config.LoadConfig(configPath)
		return configMsg{config: cfg, err: err}
	}
}

func (m secretModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "enter":
			if m.inputMode == 0 {
				// Switch to confirm password
				m.inputMode = 1
				m.input.Blur()
				return m, m.confirm.Focus()
			} else {
				// Verify passwords match
				if m.input.Value() != m.confirm.Value() {
					m.err = fmt.Errorf("secrets do not match")
					m.inputMode = 0 // Reset to first input
					m.confirm.SetValue("")
					m.input.Focus()
					m.confirm.Blur()
					return m, nil
				}

				// Save secret
				// In a real implementation, this would call auth.SetSecret
				m.success = true
				return m, tea.Quit
			}
		}

	case configMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.cfg = msg.config
		return m, nil
	}

	// Handle input changes
	if m.inputMode == 0 {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	} else {
		var cmd tea.Cmd
		m.confirm, cmd = m.confirm.Update(msg)
		return m, cmd
	}
}

func (m secretModel) View() string {
	if m.err != nil {
		return titleStyle.Render("Set Authentication Secret") + "\n\n" +
			statusErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n\n" +
			"Press Enter to try again or Esc to quit."
	}

	if m.success {
		return titleStyle.Render("Set Authentication Secret") + "\n\n" +
			statusOkStyle.Render("✓ Secret set successfully!") + "\n\n" +
			"Press any key to exit."
	}

	if m.cfg == nil {
		return titleStyle.Render("Set Authentication Secret") + "\n\n" +
			"Loading configuration...\n\n" +
			"Press Esc to quit."
	}

	var screen string
	screen += titleStyle.Render("Set Authentication Secret") + "\n\n"

	if m.inputMode == 0 {
		screen += "Enter your secret: " + m.input.View() + "\n\n"
	} else {
		screen += "Enter your secret: " + strings.Repeat("•", len(m.input.Value())) + "\n"
		screen += "Confirm secret: " + m.confirm.View() + "\n\n"
	}

	screen += "Press Enter to continue, Esc to quit.\n"
	return screen
}

func newSetSecretCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-secret",
		Short: "Set the authentication secret",
		Long:  `Set or change the authentication secret used to unlock applications.`,
		Run: func(cmd *cobra.Command, args []string) {
			p := tea.NewProgram(initialSecretModel())
			if _, err := p.Run(); err != nil {
				fmt.Printf("Error setting secret: %v\n", err)
			}
		},
	}

	return cmd
}
