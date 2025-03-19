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
	"applock-go/internal/daemon"
	"applock-go/internal/logging"
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
	for _, app := range m.config.Monitor.ProtectedApps {
		name := app
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

// Global instances used by both interactive and non-interactive modes
var (
	processMonitor *monitor.ProcessMonitor
	daemonInstance *daemon.Daemon
	clientInstance *daemon.Client
)

// initializeMonitor creates and initializes the process monitor for legacy mode (no privilege separation)
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

// initializeDaemon creates and initializes the privileged daemon
func initializeDaemon(cfg *config.Config) (*daemon.Daemon, error) {
	// Create the daemon instance
	d, err := daemon.NewDaemon(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing daemon: %w", err)
	}

	return d, nil
}

// initializeClient creates and initializes the unprivileged client
func initializeClient(cfg *config.Config) (*daemon.Client, error) {
	// Create authenticator
	authenticator, err := auth.NewAuthenticator(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing authenticator: %w", err)
	}

	// Create the client instance
	c, err := daemon.NewClient(cfg, authenticator)
	if err != nil {
		return nil, fmt.Errorf("error initializing client: %w", err)
	}

	return c, nil
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
	var (
		nonInteractive bool
		daemonMode     bool
		clientMode     bool
		legacyMode     bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the application monitor",
		Long: `Start monitoring processes and enforce application locks based on the configuration.

This command can run in either daemon mode (privileged) or client mode (unprivileged),
enabling proper privilege separation for increased security. 

In daemon mode (--daemon), it runs as root and monitors processes but delegates
authentication to the client.

In client mode (--client), it runs without root privileges and handles user
authentication requests from the daemon.

Legacy mode (--legacy) runs everything in a single process with root privileges.`,

		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate mode flags
			modes := 0
			if daemonMode {
				modes++
			}
			if clientMode {
				modes++
			}
			if legacyMode {
				modes++
			}

			if modes > 1 {
				return fmt.Errorf("cannot specify multiple modes: choose one of --daemon, --client, or --legacy")
			}

			// Default to client mode if nothing specified
			if modes == 0 {
				clientMode = true
			}

			// Validate privileges
			if daemonMode && os.Geteuid() != 0 {
				return fmt.Errorf("daemon mode requires root privileges")
			}

			if legacyMode && os.Geteuid() != 0 {
				return fmt.Errorf("legacy mode requires root privileges")
			}

			return nil
		},

		Run: func(cmd *cobra.Command, args []string) {
			// Configure logger
			logger := logging.NewLogger("applock", verbose)
			logging.DefaultLogger = logger

			// Load config
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading config: %v\n", err)
				os.Exit(1)
			}

			// Update config with command line flags
			cfg.Verbose = verbose

			// Run in the selected mode
			if daemonMode {
				runDaemonMode(cfg, nonInteractive)
			} else if clientMode {
				runClientMode(cfg, nonInteractive)
			} else {
				runLegacyMode(cfg, nonInteractive)
			}
		},
	}

	// Add mode flags
	cmd.Flags().BoolVar(&daemonMode, "daemon", false, "Run in daemon mode (privileged)")
	cmd.Flags().BoolVar(&clientMode, "client", false, "Run in client mode (unprivileged)")
	cmd.Flags().BoolVar(&legacyMode, "legacy", false, "Run in legacy mode (single process)")
	cmd.Flags().BoolVarP(&nonInteractive, "non-interactive", "n", false, "Run in non-interactive mode")

	return cmd
}

// runDaemonMode runs the application in daemon mode (privileged)
func runDaemonMode(cfg *config.Config, nonInteractive bool) {
	fmt.Println("Starting Applock in daemon mode (privileged)")

	// Initialize daemon
	d, err := initializeDaemon(cfg)
	if err != nil {
		fmt.Printf("Failed to initialize daemon: %v\n", err)
		os.Exit(1)
	}
	daemonInstance = d

	// Register process event handler
	daemonInstance.RegisterProcessEventHandler()

	// Start the daemon
	if err := daemonInstance.Start(); err != nil {
		fmt.Printf("Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Daemon started successfully - waiting for client connections")
	fmt.Println("Press Ctrl+C to stop the daemon")

	// Block until interrupted
	select {}
}

// runClientMode runs the application in client mode (unprivileged)
func runClientMode(cfg *config.Config, nonInteractive bool) {
	fmt.Println("Starting Applock in client mode (unprivileged)")

	// Initialize client
	c, err := initializeClient(cfg)
	if err != nil {
		fmt.Printf("Failed to initialize client: %v\n", err)
		os.Exit(1)
	}
	clientInstance = c

	// Connect to daemon
	if err := clientInstance.Connect(); err != nil {
		fmt.Printf("Failed to connect to daemon: %v\n", err)
		fmt.Println("Make sure the daemon is running with 'sudo applock-go run --daemon'")
		os.Exit(1)
	}

	// Ping daemon to test connection
	connected, err := clientInstance.Ping()
	if err != nil {
		fmt.Printf("Failed to ping daemon: %v\n", err)
		os.Exit(1)
	}
	if !connected {
		fmt.Println("Failed to get response from daemon")
		os.Exit(1)
	}

	fmt.Println("Connected to daemon successfully")
	fmt.Println("Press Ctrl+C to stop the client")

	// Block until interrupted
	select {}
}

// runLegacyMode runs the application in legacy mode (single process, no privilege separation)
func runLegacyMode(cfg *config.Config, nonInteractive bool) {
	fmt.Println("Starting Applock in legacy mode (single process)")

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
}
