package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"applock-go/internal/config"
)

// List model for displaying blocked applications
type listModel struct {
	table table.Model
	cfg   *config.Config
	err   error
}

func initialListModel() listModel {
	columns := []table.Column{
		{Title: "Display Name", Width: 20},
		{Title: "Path", Width: 40},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	t.SetStyles(table.Styles{
		Header:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")),
		Selected: lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#7D56F4")),
	})

	return listModel{
		table: t,
	}
}

func (m listModel) Init() tea.Cmd {
	return func() tea.Msg {
		cfg, err := config.LoadConfig(configPath)
		return configMsg{config: cfg, err: err}
	}
}

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd

	case configMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.cfg = msg.config

		// Populate table rows
		rows := []table.Row{}
		for _, app := range m.cfg.Monitor.ProtectedApps {
			displayName := filepath.Base(app)
			rows = append(rows, table.Row{displayName, app})
		}
		m.table.SetRows(rows)
		return m, nil
	}

	return m, nil
}

func (m listModel) View() string {
	if m.err != nil {
		return titleStyle.Render("Applock-Go: Blocked Applications") + "\n\n" +
			statusErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n\n" +
			"Press q to quit."
	}

	if m.cfg == nil {
		return titleStyle.Render("Applock-Go: Blocked Applications") + "\n\n" +
			"Loading configuration...\n\n" +
			"Press q to quit."
	}

	return titleStyle.Render("Applock-Go: Blocked Applications") + "\n\n" +
		tableStyle.Render(m.table.View()) + "\n\n" +
		"Press ↑/↓ to navigate, q to quit."
}

func newListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List blocked applications",
		Long:  `Show a list of applications that are being blocked by applock-go.`,
		Run: func(cmd *cobra.Command, args []string) {
			p := tea.NewProgram(initialListModel())
			if _, err := p.Run(); err != nil {
				fmt.Printf("Error listing applications: %v\n", err)
			}
		},
	}

	return cmd
}
