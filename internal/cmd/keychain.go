package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"wyrmlock/internal/keychain"
)

func newKeychainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keychain",
		Short: "Manage keychain secrets",
		Long:  `Perform operations on the system keychain (get, set, delete, check existence).`,
	}

	// Add subcommands
	cmd.AddCommand(
		newKeychainGetCommand(),
		newKeychainSetCommand(),
		newKeychainDeleteCommand(),
		newKeychainCheckCommand(),
	)

	return cmd
}

func newKeychainGetCommand() *cobra.Command {
	var service, account string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a secret from the keychain",
		Long:  `Retrieve a secret from the system keychain using service and account identifiers.`,
		Run: func(cmd *cobra.Command, args []string) {
			if service == "" || account == "" {
				fmt.Fprintln(os.Stderr, "Error: service and account are required")
				os.Exit(1)
			}

			kc, err := keychain.NewKeychainIntegration(service, account)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing keychain: %v\n", err)
				os.Exit(1)
			}

			secret, err := kc.GetSecret()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error retrieving secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(string(secret))
		},
	}

	cmd.Flags().StringVarP(&service, "service", "s", "", "Service identifier (required)")
	cmd.Flags().StringVarP(&account, "account", "a", "", "Account identifier (required)")
	cmd.MarkFlagRequired("service")
	cmd.MarkFlagRequired("account")

	return cmd
}

func newKeychainSetCommand() *cobra.Command {
	var service, account, secret string

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a secret in the keychain",
		Long:  `Store a secret in the system keychain using service and account identifiers.`,
		Run: func(cmd *cobra.Command, args []string) {
			if service == "" || account == "" || secret == "" {
				fmt.Fprintln(os.Stderr, "Error: service, account and secret are required")
				os.Exit(1)
			}

			kc, err := keychain.NewKeychainIntegration(service, account)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing keychain: %v\n", err)
				os.Exit(1)
			}

			if err := kc.SaveSecret([]byte(secret)); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Secret saved successfully for service '%s', account '%s'\n", service, account)
		},
	}

	cmd.Flags().StringVarP(&service, "service", "s", "", "Service identifier (required)")
	cmd.Flags().StringVarP(&account, "account", "a", "", "Account identifier (required)")
	cmd.Flags().StringVarP(&secret, "secret", "p", "", "Secret value to store (required)")
	cmd.MarkFlagRequired("service")
	cmd.MarkFlagRequired("account")
	cmd.MarkFlagRequired("secret")

	return cmd
}

func newKeychainDeleteCommand() *cobra.Command {
	var service, account string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a secret from the keychain",
		Long:  `Remove a secret from the system keychain using service and account identifiers.`,
		Run: func(cmd *cobra.Command, args []string) {
			if service == "" || account == "" {
				fmt.Fprintln(os.Stderr, "Error: service and account are required")
				os.Exit(1)
			}

			kc, err := keychain.NewKeychainIntegration(service, account)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing keychain: %v\n", err)
				os.Exit(1)
			}

			if err := kc.DeleteSecret(); err != nil {
				fmt.Fprintf(os.Stderr, "Error deleting secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Secret deleted successfully for service '%s', account '%s'\n", service, account)
		},
	}

	cmd.Flags().StringVarP(&service, "service", "s", "", "Service identifier (required)")
	cmd.Flags().StringVarP(&account, "account", "a", "", "Account identifier (required)")
	cmd.MarkFlagRequired("service")
	cmd.MarkFlagRequired("account")

	return cmd
}

func newKeychainCheckCommand() *cobra.Command {
	var service, account string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check if a secret exists in the keychain",
		Long:  `Check whether a secret exists in the system keychain for given service and account.`,
		Run: func(cmd *cobra.Command, args []string) {
			if service == "" || account == "" {
				fmt.Fprintln(os.Stderr, "Error: service and account are required")
				os.Exit(1)
			}

			kc, err := keychain.NewKeychainIntegration(service, account)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing keychain: %v\n", err)
				os.Exit(1)
			}

			exists, err := kc.SecretExists()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking secret: %v\n", err)
				os.Exit(1)
			}

			if exists {
				fmt.Printf("Secret exists for service '%s', account '%s'\n", service, account)
			} else {
				fmt.Printf("No secret found for service '%s', account '%s'\n", service, account)
			}
		},
	}

	cmd.Flags().StringVarP(&service, "service", "s", "", "Service identifier (required)")
	cmd.Flags().StringVarP(&account, "account", "a", "", "Account identifier (required)")
	cmd.MarkFlagRequired("service")
	cmd.MarkFlagRequired("account")

	return cmd
}
