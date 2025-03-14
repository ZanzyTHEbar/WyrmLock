package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	// List of applications to be locked
	BlockedApps []BlockedApp `mapstructure:"blockedApps"`

	// Authentication configuration
	Auth AuthConfig `mapstructure:"auth"`

	// Optional keychain service name for integration with Linux keychain
	KeychainService string `mapstructure:"keychainService"`

	// Optional keychain account name for integration with Linux keychain
	KeychainAccount string `mapstructure:"keychainAccount"`

	// Whether to enable verbose logging
	Verbose bool `mapstructure:"verbose"`
}

// BlockedApp represents an application that should be locked
type BlockedApp struct {
	// Name or path of the executable
	Path string `mapstructure:"path"`

	// Optional display name for user interface
	DisplayName string `mapstructure:"displayName,omitempty"`
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	// Whether to use ZKP (Themis Secure Comparator)
	UseZeroKnowledgeProof bool `mapstructure:"useZeroKnowledgeProof"`

	// Path to the secret data file if not using keychain
	SecretPath string `mapstructure:"secretPath,omitempty"`

	// Hash algorithm to use (bcrypt, argon2id, etc.)
	// Only used if not using ZKP
	HashAlgorithm string `mapstructure:"hashAlgorithm,omitempty"`

	// GUI type to use for the authentication prompt
	// Can be "gtk", "webkit2gtk", or "indicator"
	GuiType string `mapstructure:"guiType"`
}

// LoadConfig loads the configuration from the specified file
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Set default configuration type to TOML
	v.SetConfigType("toml")

	// Setup config file path
	configDir := filepath.Dir(configPath)
	configName := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))

	v.SetConfigName(configName)
	v.AddConfigPath(configDir)

	// Set environment variable prefix for config overrides
	v.SetEnvPrefix("APPLOCK")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults
	setConfigDefaults(v)

	// Read the configuration file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, we'll use defaults
			return nil, fmt.Errorf("config file not found at %s: %w", configPath, err)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the configuration
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate the configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// setConfigDefaults sets default values for configuration
func setConfigDefaults(v *viper.Viper) {
	// Default GUI type
	v.SetDefault("auth.guiType", "gtk")

	// Default to using ZKP
	v.SetDefault("auth.useZeroKnowledgeProof", true)

	// Default secret path
	v.SetDefault("auth.secretPath", "/etc/applock-go/secret")

	// Default keychain settings
	v.SetDefault("keychainService", "applock-go")
	v.SetDefault("keychainAccount", "default")

	// Default to verbose logging
	v.SetDefault("verbose", false)
}

// validateConfig checks if the loaded configuration is valid
func validateConfig(cfg *Config) error {
	// Check if there are any blocked applications
	if len(cfg.BlockedApps) == 0 {
		return fmt.Errorf("no blocked applications specified")
	}

	// Check GUI type
	switch cfg.Auth.GuiType {
	case "gtk", "webkit2gtk", "indicator":
		// Valid GUI types
	default:
		return fmt.Errorf("invalid GUI type: %s", cfg.Auth.GuiType)
	}

	// Check ZKP configuration
	if cfg.Auth.UseZeroKnowledgeProof {
		if cfg.KeychainService == "" || cfg.KeychainAccount == "" {
			if cfg.Auth.SecretPath == "" {
				return fmt.Errorf("when using ZKP, either keychain or secret file must be specified")
			}

			// Check if secret file exists
			if _, err := os.Stat(cfg.Auth.SecretPath); os.IsNotExist(err) {
				return fmt.Errorf("secret file does not exist: %s", cfg.Auth.SecretPath)
			}
		}
	} else {
		// Hash algorithm must be specified if not using ZKP
		switch cfg.Auth.HashAlgorithm {
		case "bcrypt", "argon2id", "scrypt", "pbkdf2":
			// Valid hash algorithms
		default:
			return fmt.Errorf("invalid hash algorithm: %s", cfg.Auth.HashAlgorithm)
		}
	}

	return nil
}

// CreateDefaultConfig creates a default configuration file at the specified path
func CreateDefaultConfig(path string) error {
	// Create a new Viper instance
	v := viper.New()
	v.SetConfigType("toml")

	// Set default values
	v.Set("blockedApps", []map[string]string{
		{"path": "/usr/bin/firefox", "displayName": "Firefox"},
		{"path": "/usr/bin/chromium", "displayName": "Chromium"},
	})

	// Auth settings
	v.Set("auth.useZeroKnowledgeProof", true)
	v.Set("auth.guiType", "gtk")
	v.Set("auth.secretPath", "/etc/applock-go/secret")

	// Keychain settings
	v.Set("keychainService", "applock-go")
	v.Set("keychainAccount", "default")

	// Logging
	v.Set("verbose", true)

	// Create parent directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write the configuration file
	if err := v.WriteConfigAs(path); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
