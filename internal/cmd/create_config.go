package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"wyrmlock/internal/config"
)

func newCreateConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-config [path]",
		Short: "Create a default configuration file",
		Long:  `Generate a default configuration file at the specified path or use the default path.`,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := configPath
			if len(args) > 0 {
				path = args[0]
			}

			if err := config.CreateDefaultConfig(path); err != nil {
				fmt.Printf("Error creating configuration: %v\n", err)
				return
			}

			fmt.Printf("Default configuration created at %s\n", path)
		},
	}

	return cmd
}
