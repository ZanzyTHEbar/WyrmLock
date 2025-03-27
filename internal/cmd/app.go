package cmd

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"wyrmlock/internal/config"
)

// Add a new application to the protected list
func newAppAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [path]",
		Short: "Add application to protected list",
		Long:  `Add an application to the list of applications that require authentication.`,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Get flags
			displayName, _ := cmd.Flags().GetString("name")
			verifyHash, _ := cmd.Flags().GetBool("verify-hash")
			exactPath, _ := cmd.Flags().GetBool("exact-path")
			hashAlgorithm, _ := cmd.Flags().GetString("hash-algorithm")
			
			// Load configuration
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading configuration: %v\n", err)
				return
			}
			
			// Get absolute path
			appPath := args[0]
			absPath, err := filepath.Abs(appPath)
			if err != nil {
				fmt.Printf("Error getting absolute path: %v\n", err)
				return
			}
			
			// Check if file exists
			if _, err := os.Stat(absPath); os.IsNotExist(err) {
				fmt.Printf("Application file does not exist: %s\n", absPath)
				return
			}
			
			// Create new BlockedApp entry
			blockedApp := config.BlockedApp{
				Path:            absPath,
				DisplayName:     displayName,
				EnforcePathExact: exactPath,
				EnforceFileHash: verifyHash,
			}
			
			// If hash verification is enabled, compute hash
			if verifyHash {
				var hashFunc func() hash.Hash
				
				switch hashAlgorithm {
				case "sha256":
					hashFunc = sha256.New
				case "sha512":
					hashFunc = sha512.New
				default:
					fmt.Printf("Unsupported hash algorithm: %s. Using SHA-256.\n", hashAlgorithm)
					hashFunc = sha256.New
				}
				
				// Open the file
				file, err := os.Open(absPath)
				if err != nil {
					fmt.Printf("Error opening file for hashing: %v\n", err)
					return
				}
				defer file.Close()
				
				// Create hash
				h := hashFunc()
				if _, err := io.Copy(h, file); err != nil {
					fmt.Printf("Error computing hash: %v\n", err)
					return
				}
				
				// Store hash
				blockedApp.FileHash = hex.EncodeToString(h.Sum(nil))
				fmt.Printf("Computed %s hash: %s\n", hashAlgorithm, blockedApp.FileHash)
			}
			
			// Add to configuration
			cfg.BlockedApps = append(cfg.BlockedApps, blockedApp)
			
			// Also add to legacy protected apps list for backwards compatibility
			found := false
			for _, path := range cfg.Monitor.ProtectedApps {
				if path == absPath {
					found = true
					break
				}
			}
			
			if !found {
				cfg.Monitor.ProtectedApps = append(cfg.Monitor.ProtectedApps, absPath)
			}
			
			// Save configuration
			if err := config.SaveConfig(cfg, configPath); err != nil {
				fmt.Printf("Error saving configuration: %v\n", err)
				return
			}
			
			fmt.Printf("Added %s to protected applications.\n", absPath)
			if verifyHash {
				fmt.Printf("Hash verification enabled for this application.\n")
			}
		},
	}
	
	// Add flags
	cmd.Flags().StringP("name", "n", "", "Display name for the application")
	cmd.Flags().BoolP("verify-hash", "v", false, "Verify executable hash")
	cmd.Flags().BoolP("exact-path", "e", false, "Require exact path matching")
	cmd.Flags().String("hash-algorithm", "sha256", "Hash algorithm to use (sha256 or sha512)")
	
	return cmd
}

// Remove an application from the protected list
func newAppRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove [path]",
		Short: "Remove application from protected list",
		Long:  `Remove an application from the list of applications that require authentication.`,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Load configuration
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading configuration: %v\n", err)
				return
			}
			
			// Get absolute path
			appPath := args[0]
			absPath, err := filepath.Abs(appPath)
			if err != nil {
				fmt.Printf("Error getting absolute path: %v\n", err)
				return
			}
			
			// Remove from BlockedApps
			var newBlockedApps []config.BlockedApp
			removed := false
			
			for _, app := range cfg.BlockedApps {
				if app.Path != absPath {
					newBlockedApps = append(newBlockedApps, app)
				} else {
					removed = true
				}
			}
			
			// Only update if something was removed
			if removed {
				cfg.BlockedApps = newBlockedApps
			}
			
			// Remove from legacy protected apps list
			var newProtectedApps []string
			legacyRemoved := false
			
			for _, path := range cfg.Monitor.ProtectedApps {
				if path != absPath {
					newProtectedApps = append(newProtectedApps, path)
				} else {
					legacyRemoved = true
				}
			}
			
			if legacyRemoved {
				cfg.Monitor.ProtectedApps = newProtectedApps
			}
			
			// If nothing was removed, notify user
			if !removed && !legacyRemoved {
				fmt.Printf("Application %s was not found in protected apps list.\n", absPath)
				return
			}
			
			// Save configuration
			if err := config.SaveConfig(cfg, configPath); err != nil {
				fmt.Printf("Error saving configuration: %v\n", err)
				return
			}
			
			fmt.Printf("Removed %s from protected applications.\n", absPath)
		},
	}
	
	return cmd
}

// List protected applications
func newAppListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List protected applications",
		Long:  `List all applications that require authentication.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Load configuration
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading configuration: %v\n", err)
				return
			}
			
			// Print header
			fmt.Println("Protected Applications:")
			fmt.Println("=======================")
			
			// Print blocked apps with details
			if len(cfg.BlockedApps) > 0 {
				for i, app := range cfg.BlockedApps {
					displayName := app.DisplayName
					if displayName == "" {
						displayName = filepath.Base(app.Path)
					}
					
					fmt.Printf("%d. %s\n", i+1, displayName)
					fmt.Printf("   Path: %s\n", app.Path)
					fmt.Printf("   Exact Path Matching: %v\n", app.EnforcePathExact)
					fmt.Printf("   Hash Verification: %v\n", app.EnforceFileHash)
					if app.EnforceFileHash && app.FileHash != "" {
						fmt.Printf("   Hash: %s\n", app.FileHash)
					}
					fmt.Println()
				}
			} else if len(cfg.Monitor.ProtectedApps) > 0 {
				// Legacy format
				for i, path := range cfg.Monitor.ProtectedApps {
					fmt.Printf("%d. %s\n", i+1, path)
				}
			} else {
				fmt.Println("No protected applications configured.")
			}
			
			// Print hash verification setting
			fmt.Println("Global Settings:")
			fmt.Printf("Hash Verification Enabled: %v\n", cfg.Monitor.VerifyHashes)
			fmt.Printf("Hash Algorithm: %s\n", cfg.Monitor.HashAlgorithm)
		},
	}
	
	return cmd
}

// Enable or disable hash verification
func newAppVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [on|off]",
		Short: "Enable or disable hash verification",
		Long:  `Enable or disable verification of executable hashes for protected applications.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Parse argument
			enable := false
			switch args[0] {
			case "on", "enable", "true":
				enable = true
			case "off", "disable", "false":
				enable = false
			default:
				fmt.Printf("Invalid argument: %s. Use 'on' or 'off'.\n", args[0])
				return
			}
			
			// Load configuration
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading configuration: %v\n", err)
				return
			}
			
			// Get flags
			hashAlgorithm, _ := cmd.Flags().GetString("hash-algorithm")
			
			// Update configuration
			cfg.Monitor.VerifyHashes = enable
			if hashAlgorithm != "" {
				cfg.Monitor.HashAlgorithm = hashAlgorithm
			}
			
			// Save configuration
			if err := config.SaveConfig(cfg, configPath); err != nil {
				fmt.Printf("Error saving configuration: %v\n", err)
				return
			}
			
			if enable {
				fmt.Printf("Hash verification enabled. Algorithm: %s\n", cfg.Monitor.HashAlgorithm)
			} else {
				fmt.Println("Hash verification disabled.")
			}
		},
	}
	
	// Add flags
	cmd.Flags().String("hash-algorithm", "", "Hash algorithm to use (sha256 or sha512)")
	
	return cmd
}

// Update hash for an existing protected application
func newAppUpdateHashCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-hash [path]",
		Short: "Update hash for a protected application",
		Long:  `Compute and update the hash for an existing protected application.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Load configuration
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading configuration: %v\n", err)
				return
			}
			
			// Get absolute path
			appPath := args[0]
			absPath, err := filepath.Abs(appPath)
			if err != nil {
				fmt.Printf("Error getting absolute path: %v\n", err)
				return
			}
			
			// Get hash algorithm
			hashAlgorithm, _ := cmd.Flags().GetString("hash-algorithm")
			if hashAlgorithm == "" {
				hashAlgorithm = cfg.Monitor.HashAlgorithm
			}
			
			// Verify algorithm
			var hashFunc func() hash.Hash
			switch hashAlgorithm {
			case "sha256":
				hashFunc = sha256.New
			case "sha512":
				hashFunc = sha512.New
			default:
				fmt.Printf("Unsupported hash algorithm: %s. Using SHA-256.\n", hashAlgorithm)
				hashFunc = sha256.New
				hashAlgorithm = "sha256"
			}
			
			// Check if file exists
			if _, err := os.Stat(absPath); os.IsNotExist(err) {
				fmt.Printf("Application file does not exist: %s\n", absPath)
				return
			}
			
			// Compute hash
			file, err := os.Open(absPath)
			if err != nil {
				fmt.Printf("Error opening file for hashing: %v\n", err)
				return
			}
			defer file.Close()
			
			h := hashFunc()
			if _, err := io.Copy(h, file); err != nil {
				fmt.Printf("Error computing hash: %v\n", err)
				return
			}
			
			fileHash := hex.EncodeToString(h.Sum(nil))
			
			// Find and update app in configuration
			found := false
			for i, app := range cfg.BlockedApps {
				if app.Path == absPath {
					app.FileHash = fileHash
					app.EnforceFileHash = true
					cfg.BlockedApps[i] = app
					found = true
					break
				}
			}
			
			if !found {
				// Create new entry
				blockedApp := config.BlockedApp{
					Path:            absPath,
					DisplayName:     filepath.Base(absPath),
					EnforcePathExact: false,
					EnforceFileHash: true,
					FileHash:        fileHash,
				}
				
				cfg.BlockedApps = append(cfg.BlockedApps, blockedApp)
				
				// Also add to legacy protected apps list for backwards compatibility
				legacyFound := false
				for _, path := range cfg.Monitor.ProtectedApps {
					if path == absPath {
						legacyFound = true
						break
					}
				}
				
				if !legacyFound {
					cfg.Monitor.ProtectedApps = append(cfg.Monitor.ProtectedApps, absPath)
				}
			}
			
			// Save configuration
			if err := config.SaveConfig(cfg, configPath); err != nil {
				fmt.Printf("Error saving configuration: %v\n", err)
				return
			}
			
			fmt.Printf("Updated hash for %s:\n", absPath)
			fmt.Printf("Algorithm: %s\n", hashAlgorithm)
			fmt.Printf("Hash: %s\n", fileHash)
		},
	}
	
	// Add flags
	cmd.Flags().String("hash-algorithm", "", "Hash algorithm to use (sha256 or sha512)")
	
	return cmd
}

// newAppCommand creates a new app command
func newAppCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Manage protected applications",
		Long:  `Add, remove, and list protected applications.`,
	}
	
	// Add subcommands
	cmd.AddCommand(newAppAddCommand())
	cmd.AddCommand(newAppRemoveCommand())
	cmd.AddCommand(newAppListCommand())
	cmd.AddCommand(newAppVerifyCommand())
	cmd.AddCommand(newAppUpdateHashCommand())
	
	return cmd
} 