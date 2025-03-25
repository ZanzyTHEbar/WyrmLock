package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles for the status UI
var (
	statusTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#7D56F4")).
				Padding(0, 1).
				MarginBottom(1)

	statusConnectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#10B981"))

	statusDisconnectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#EF4444"))

	statusLabelStyle = lipgloss.NewStyle().
				Bold(true).
				Width(20)

	statusValueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#8BE9FD"))

	statusTableStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("#7D56F4"))

	statusWarningStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F59E0B"))

	statusErrorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#EF4444"))
)

// StatusUI is a terminal UI for displaying daemon status
type StatusUI struct {
	monitor        *StatusMonitor
	status         DaemonStatus
	processTable   table.Model
	lastUpdateTime time.Time
	updateChan     chan DaemonStatus
	width          int
	height         int
}

// NewStatusUI creates a new terminal UI for daemon status
func NewStatusUI(monitor *StatusMonitor) *StatusUI {
	// Create the process table
	columns := []table.Column{
		{Title: "PID", Width: 10},
		{Title: "Command", Width: 30},
		{Title: "Status", Width: 15},
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

	ui := &StatusUI{
		monitor:      monitor,
		processTable: t,
		updateChan:   make(chan DaemonStatus, 10),
		width:        80,
		height:       24,
	}

	// Register status listener
	monitor.AddStatusListener(func(status DaemonStatus) {
		ui.updateChan <- status
	})

	return ui
}

// Start initializes and starts the terminal UI
func (ui *StatusUI) Start() *tea.Program {
	p := tea.NewProgram(ui)
	return p
}

// Init initializes the UI model
func (ui *StatusUI) Init() tea.Cmd {
	return ui.waitForStatusUpdate()
}

// waitForStatusUpdate waits for status updates from the monitor
func (ui *StatusUI) waitForStatusUpdate() tea.Cmd {
	return func() tea.Msg {
		status := <-ui.updateChan
		return statusUpdateMsg(status)
	}
}

// statusUpdateMsg is a message type for status updates
type statusUpdateMsg DaemonStatus

// Update handles UI events and state changes
func (ui *StatusUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return ui, tea.Quit
		}

	case tea.WindowSizeMsg:
		ui.width = msg.Width
		ui.height = msg.Height
		ui.processTable.SetWidth(msg.Width - 10)
		return ui, nil

	case statusUpdateMsg:
		ui.status = DaemonStatus(msg)
		ui.lastUpdateTime = time.Now()

		// Update process table
		rows := []table.Row{}
		for _, p := range ui.status.ActiveProcesses {
			status := "Locked"
			if p.Allowed {
				status = "Allowed"
			}
			rows = append(rows, table.Row{
				fmt.Sprintf("%d", p.PID),
				p.Command,
				status,
			})
		}
		ui.processTable.SetRows(rows)

		return ui, ui.waitForStatusUpdate()
	}

	return ui, nil
}

// View renders the UI
func (ui *StatusUI) View() string {
	var view strings.Builder

	// Title
	view.WriteString(statusTitleStyle.Render("Applock-Go Status Monitor"))
	view.WriteString("\n\n")

	// Connection status
	connStatus := "Disconnected"
	connStyle := statusDisconnectedStyle
	if ui.status.IsConnected {
		connStatus = "Connected"
		connStyle = statusConnectedStyle

		// Add connection time
		if !ui.status.ConnectedSince.IsZero() {
			duration := time.Since(ui.status.ConnectedSince).Round(time.Second)
			connStatus = fmt.Sprintf("Connected (uptime: %s)", duration)
		}
	}
	view.WriteString(fmt.Sprintf("%s %s\n",
		statusLabelStyle.Render("Daemon Status:"),
		connStyle.Render(connStatus)))

	// Version
	view.WriteString(fmt.Sprintf("%s %s\n",
		statusLabelStyle.Render("Version:"),
		statusValueStyle.Render(ui.status.Version)))

	// Ping latency
	if ui.status.IsConnected {
		view.WriteString(fmt.Sprintf("%s %s\n",
			statusLabelStyle.Render("Ping Latency:"),
			statusValueStyle.Render(fmt.Sprintf("%d ms", ui.status.PingLatency.Milliseconds()))))
	}

	// Protected apps
	view.WriteString(fmt.Sprintf("%s %s\n",
		statusLabelStyle.Render("Protected Apps:"),
		statusValueStyle.Render(fmt.Sprintf("%d", ui.status.BlockedApps))))

	// Brute force events
	if ui.status.BruteForceEvents > 0 {
		view.WriteString(fmt.Sprintf("%s %s\n",
			statusLabelStyle.Render("Brute Force Events:"),
			statusWarningStyle.Render(fmt.Sprintf("%d", ui.status.BruteForceEvents))))
	}

	view.WriteString("\n")

	// System errors
	if len(ui.status.SystemErrors) > 0 {
		view.WriteString(statusErrorStyle.Render("Recent System Errors:"))
		view.WriteString("\n")

		for _, err := range ui.status.SystemErrors {
			view.WriteString(statusErrorStyle.Render("• " + err))
			view.WriteString("\n")
		}
		view.WriteString("\n")
	}

	// Active processes section
	if len(ui.status.ActiveProcesses) > 0 {
		view.WriteString("Active Monitored Processes:\n")
		view.WriteString(statusTableStyle.Render(ui.processTable.View()))
	} else {
		view.WriteString("No active monitored processes.\n")
	}

	// Footer
	view.WriteString("\n")
	view.WriteString(fmt.Sprintf("Last updated: %s\n", ui.lastUpdateTime.Format("15:04:05")))
	view.WriteString("Press q to quit")

	return view.String()
}
