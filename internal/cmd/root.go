package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	configPath string
	verbose    bool
)

// NewRootCommand creates the root command for the applock-go CLI
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "applock-go",
		Short: "A security tool to control access to applications",
		Long: `Applock-go is a Linux security tool that controls access to specific applications
by requiring cryptographic authentication before they can be launched.

It monitors process execution system-wide and intercepts launches of configured
applications. When a protected application is launched, it is suspended until
the user provides the correct authentication.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Check if running as root for commands that require it
			if cmd.Name() != "version" && cmd.Name() != "help" && cmd.Name() != "create-config" && 
			   cmd.Name() != "keychain" && os.Geteuid() != 0 {
				fmt.Fprintln(os.Stderr, "This command requires root privileges to run")
				os.Exit(1)
			}
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/applock-go/config.toml", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(
		newAppCommand(),
		newRunCommand(),
		newSetSecretCommand(),
		newCreateConfigCommand(),
		newListCommand(),
		newVersionCommand(),
		newConfigCommand(),
		newKeychainCommand(), // Add the new keychain command
	)

	return rootCmd
}
