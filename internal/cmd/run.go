package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"applock-go/internal/auth"
	"applock-go/internal/config"
	"applock-go/internal/monitor"
)

var (
	// Styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			MarginBottom(1)

	statusOkStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8BE9FD"))

	statusErrorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF5555"))

	tableStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#7D56F4"))
)

// Model represents the state of the TUI
type runModel struct {
	config         *config.Config
	processSpinner spinner.Model
	processTable   table.Model
	processes      []monitor.ProcessInfo
	ready          bool
	err            error
}

func initialRunModel() runModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))

	columns := []table.Column{
		{Title: "PID", Width: 10},
		{Title: "Command", Width: 30},
		{Title: "Status", Width: 20},
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

	return runModel{
		processSpinner: s,
		processTable:   t,
		processes:      []monitor.ProcessInfo{},
	}
}

func (m runModel) Init() tea.Cmd {
	return tea.Batch(
		m.processSpinner.Tick,
		loadConfigCmd(configPath),
	)
}

func (m runModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}

	case configMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.config = msg.config
		m.ready = true
		return m, startMonitoringCmd()

	case monitorStartedMsg:
		return m, pollProcessesCmd()

	case processUpdateMsg:
		m.processes = msg.processes
		rows := []table.Row{}
		for _, p := range m.processes {
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
		m.processTable.SetRows(rows)
		return m, tea.Batch(
			m.processSpinner.Tick,
			timerCmd(1*time.Second, func() tea.Msg {
				return pollProcessesMsg{}
			}),
		)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.processSpinner, cmd = m.processSpinner.Update(msg)
		return m, cmd

	case errorMsg:
		m.err = msg.err
		return m, nil
	}

	return m, nil
}

func (m runModel) View() string {
	if m.err != nil {
		return titleStyle.Render("Applock-Go") + "\n" +
			statusErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n\n" +
			"Press q to quit."
	}

	if !m.ready {
		return titleStyle.Render("Applock-Go") + "\n" +
			"Loading configuration... " + m.processSpinner.View() + "\n\n" +
			"Press q to quit."
	}

	blockedApps := "\nProtecting applications:\n"
	for _, app := range m.config.BlockedApps {
		name := app.DisplayName
		if name == "" {
			name = app.Path
		}
		blockedApps += fmt.Sprintf("  • %s\n", name)
	}

	status := statusOkStyle.Render("✓ Monitoring active")
	return titleStyle.Render("Applock-Go") + "\n" +
		status + "\n" +
		blockedApps + "\n" +
		tableStyle.Render(m.processTable.View()) + "\n\n" +
		"Press q to quit."
}

// Custom messages
type configMsg struct {
	config *config.Config
	err    error
}

type monitorStartedMsg struct{}
type pollProcessesMsg struct{}
type processUpdateMsg struct {
	processes []monitor.ProcessInfo
}
type errorMsg struct {
	err error
}

// Helper function for creating timer-based commands
func timerCmd(duration time.Duration, fn func() tea.Msg) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(duration)
		return fn()
	}
}

// Commands
func loadConfigCmd(path string) tea.Cmd {
	return func() tea.Msg {
		cfg, err := config.LoadConfig(path)
		return configMsg{config: cfg, err: err}
	}
}

// Global monitor instance used by both interactive and non-interactive modes
var processMonitor *monitor.ProcessMonitor

// initializeMonitor creates and initializes the process monitor
func initializeMonitor(cfg *config.Config) (*monitor.ProcessMonitor, error) {
	// Create authenticator using cfg
	authenticator, err := auth.NewAuthenticator(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing authenticator: %w", err)
	}

	// Initialize the process monitor with cfg and authenticator
	mon, err := monitor.NewProcessMonitor(cfg, authenticator)
	if err != nil {
		return nil, fmt.Errorf("error initializing process monitor: %w", err)
	}

	return mon, nil
}

// displayProcesses formats and prints process information
func displayProcesses(processes []monitor.ProcessInfo) {
	fmt.Println("Active Processes:")
	if len(processes) == 0 {
		fmt.Println("  No monitored processes found")
	} else {
		for _, p := range processes {
			status := "Locked"
			if p.Allowed {
				status = "Allowed"
			}
			fmt.Printf("PID: %d | Command: %s | Status: %s\n", p.PID, p.Command, status)
		}
	}
	fmt.Println("-----")
}

func startMonitoringCmd() tea.Cmd {
	return func() tea.Msg {
		// Create and initialize monitor if not already done
		if processMonitor == nil {
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return errorMsg{err: fmt.Errorf("failed to load config: %w", err)}
			}
			
			mon, err := initializeMonitor(cfg)
			if err != nil {
				return errorMsg{err: err}
			}
			
			processMonitor = mon
		}
		
		// Start the monitor
		if err := processMonitor.Start(); err != nil {
			return errorMsg{err: fmt.Errorf("failed to start monitor: %w", err)}
		}
		
		return monitorStartedMsg{}
	}
}

func pollProcessesCmd() tea.Cmd {
	return func() tea.Msg {
		if processMonitor == nil {
			return errorMsg{err: errors.New("process monitor not initialized")}
		}
		
		processes, err := processMonitor.PollProcesses()
		if err != nil {
			return errorMsg{err: fmt.Errorf("failed to poll processes: %w", err)}
		}
		
		return processUpdateMsg{processes: processes}
	}
}

func newRunCommand() *cobra.Command {
	var nonInteractive bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the application monitor",
		Long:  `Start monitoring processes and enforce application locks based on the configuration.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Load config first (needed for both modes)
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading config: %v\n", err)
				os.Exit(1)
			}
			
			// Initialize monitor (shared between modes)
			mon, err := initializeMonitor(cfg)
			if err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(1)
			}
			processMonitor = mon
			
			// Start the monitor
			if err := processMonitor.Start(); err != nil {
				fmt.Printf("Error starting monitor: %v\n", err)
				os.Exit(1)
			}

			if nonInteractive {
				// Non-interactive mode: poll and display processes periodically
				fmt.Println("Non-interactive mode: monitoring processes")
				for {
					processes, err := processMonitor.PollProcesses()
					if err != nil {
						fmt.Printf("Error polling processes: %v\n", err)
					} else {
						displayProcesses(processes)
					}
					time.Sleep(1 * time.Second)
				}
			} else {
				// Interactive mode: detect TTY and use Bubble Tea alt-screen mode if available
				var opts []tea.ProgramOption
				if isatty.IsTerminal(os.Stdin.Fd()) {
					opts = []tea.ProgramOption{tea.WithAltScreen()}
				}
				p := tea.NewProgram(initialRunModel(), opts...)
				if _, err := p.Run(); err != nil {
					fmt.Printf("Error running application: %v\n", err)
					os.Exit(1)
				}
			}
		},
	}
	cmd.Flags().BoolVarP(&nonInteractive, "non-interactive", "n", false, "Run in non-interactive mode")
	return cmd
}
