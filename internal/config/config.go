package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	// Whether to enable verbose logging
	Verbose bool `mapstructure:"verbose"`

	// SocketPath is the path to the Unix domain socket for daemon communication
	SocketPath string `json:"socket_path"`

	// Auth contains authentication-related configuration
	Auth AuthConfig `json:"auth"`

	// Monitor contains process monitoring configuration
	Monitor MonitorConfig `json:"monitor"`

	// BlockedApps is a list of applications that require authentication
	BlockedApps []BlockedApp `json:"blocked_apps"`

	// KeychainService is the name of the keychain service
	KeychainService string `json:"keychain_service,omitempty"`

	// KeychainAccount is the name of the keychain account
	KeychainAccount string `json:"keychain_account,omitempty"`
}

// AuthConfig contains authentication-related configuration
type AuthConfig struct {
	// GuiType specifies the type of GUI to use for authentication dialogs
	GuiType string `json:"gui_type"`

	// HashAlgorithm specifies the password hashing algorithm
	HashAlgorithm string `json:"hash_algorithm"`

	// Salt is used for password hashing
	Salt string `json:"salt"`

	// MaxAttempts is the maximum number of failed authentication attempts before lockout
	MaxAttempts int `json:"max_attempts"`

	// LockoutDuration is the duration of lockout after max attempts in seconds
	LockoutDuration int `json:"lockout_duration"`

	// UseZeroKnowledgeProof enables zero-knowledge proof authentication
	UseZeroKnowledgeProof bool `json:"use_zero_knowledge_proof"`

	// SecretPath is the path to the secret data file
	SecretPath string `json:"secret_path,omitempty"`
}

// MonitorConfig contains process monitoring configuration
type MonitorConfig struct {
	// ScanInterval is the interval between process scans in seconds
	ScanInterval int `json:"scan_interval"`

	// ProtectedApps is a list of applications that require authentication
	ProtectedApps []string `json:"protected_apps"`

	// VerifyHashes enables verification of executable hashes
	VerifyHashes bool `json:"verify_hashes"`

	// HashAlgorithm specifies which hash algorithm to use for verification
	HashAlgorithm string `json:"hash_algorithm"`
}

// BlockedApp represents an application that requires authentication
type BlockedApp struct {
	// Path is the path to the executable
	Path string `json:"path"`

	// DisplayName is a user-friendly name for the application
	DisplayName string `json:"display_name,omitempty"`

	// EnforcePathExact requires exact path matching
	EnforcePathExact bool `json:"enforce_path_exact,omitempty"`

	// EnforceFileHash enables executable hash verification
	EnforceFileHash bool `json:"enforce_file_hash,omitempty"`

	// FileHash is the SHA-256 hash of the executable
	FileHash string `json:"file_hash,omitempty"`
}

// LoadConfig loads the configuration from the specified file
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	setConfigDefaults(v)

	// Set config file path
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config in default locations
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/applock")
		v.AddConfigPath("$HOME/.config/applock")
		v.AddConfigPath(".")
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}
		// Config file not found, use defaults
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(v.ConfigFileUsed())
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %v", err)
	}

	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Validate the configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &cfg, nil
}

// setConfigDefaults sets default values for the configuration
func setConfigDefaults(v *viper.Viper) {
	// Default GUI type
	v.SetDefault("auth.gui_type", "gtk")

	// Default to using ZKP
	v.SetDefault("auth.use_zero_knowledge_proof", true)

	// Default hash algorithm
	v.SetDefault("auth.hash_algorithm", "argon2id")

	// Default max attempts
	v.SetDefault("auth.max_attempts", 3)

	// Default lockout duration (5 minutes)
	v.SetDefault("auth.lockout_duration", 300)

	// Default scan interval (1 second)
	v.SetDefault("monitor.scan_interval", 1)
	
	// Default to not verifying hashes initially for compatibility
	v.SetDefault("monitor.verify_hashes", false)
	
	// Default hash algorithm for verification
	v.SetDefault("monitor.hash_algorithm", "sha256")

	// Default socket path
	v.SetDefault("socket_path", "/var/run/applock-daemon.sock")

	// Default to non-verbose logging
	v.SetDefault("verbose", false)
}

// validateConfig checks if the loaded configuration is valid
func validateConfig(cfg *Config) error {
	// Check if there are any protected applications
	if len(cfg.Monitor.ProtectedApps) == 0 {
		return fmt.Errorf("no protected applications specified")
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
		if cfg.Auth.SecretPath == "" {
			return fmt.Errorf("when using ZKP, secret file must be specified")
		}

		// Check if secret file exists
		if _, err := os.Stat(cfg.Auth.SecretPath); os.IsNotExist(err) {
			return fmt.Errorf("secret file does not exist: %s", cfg.Auth.SecretPath)
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
	
	// Check hash algorithm for process verification
	if cfg.Monitor.VerifyHashes {
		switch cfg.Monitor.HashAlgorithm {
		case "sha256", "sha512":
			// Valid hash algorithms
		default:
			return fmt.Errorf("invalid process verification hash algorithm: %s", cfg.Monitor.HashAlgorithm)
		}
	}

	return nil
}

// CreateDefaultConfig creates a default configuration file at the specified path
func CreateDefaultConfig(path string) error {
	// Create a new Viper instance
	v := viper.New()
	v.SetConfigType("yaml")

	// Set default values
	v.Set("monitor.protected_apps", []string{
		"/usr/bin/firefox",
		"/usr/bin/chromium",
	})
	v.Set("monitor.scan_interval", 1)
	v.Set("monitor.verify_hashes", false)
	v.Set("monitor.hash_algorithm", "sha256")

	// Auth settings
	v.Set("auth.use_zero_knowledge_proof", true)
	v.Set("auth.gui_type", "gtk")
	v.Set("auth.hash_algorithm", "argon2id")
	v.Set("auth.max_attempts", 3)
	v.Set("auth.lockout_duration", 300)
	v.Set("auth.secret_path", "/etc/applock-go/secret")

	// Socket path
	v.Set("socket_path", "/var/run/applock-daemon.sock")

	// Logging
	v.Set("verbose", true)

	// Create parent directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Write the configuration file
	if err := v.WriteConfigAs(path); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// SaveConfig saves the configuration to the specified file path
func SaveConfig(cfg *Config, configPath string) error {
	// Create the directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Initialize viper for saving
	v := viper.New()

	// Set config values from our Config struct
	v.Set("monitor.protected_apps", cfg.Monitor.ProtectedApps)
	v.Set("monitor.scan_interval", cfg.Monitor.ScanInterval)
	v.Set("monitor.verify_hashes", cfg.Monitor.VerifyHashes)
	v.Set("monitor.hash_algorithm", cfg.Monitor.HashAlgorithm)

	// Auth settings
	v.Set("auth.use_zero_knowledge_proof", cfg.Auth.UseZeroKnowledgeProof)
	v.Set("auth.hash_algorithm", cfg.Auth.HashAlgorithm)
	v.Set("auth.secret_path", cfg.Auth.SecretPath)
	v.Set("auth.gui_type", cfg.Auth.GuiType)
	v.Set("auth.max_attempts", cfg.Auth.MaxAttempts)
	v.Set("auth.lockout_duration", cfg.Auth.LockoutDuration)

	// Socket path
	v.Set("socket_path", cfg.SocketPath)

	// Other settings
	v.Set("verbose", cfg.Verbose)

	// Set the config file path and type
	ext := filepath.Ext(configPath)
	if ext != "" {
		v.SetConfigType(strings.TrimPrefix(ext, "."))
	} else {
		v.SetConfigType("yaml")
	}
	v.SetConfigFile(configPath)

	// Write the config to file
	if err := v.WriteConfig(); err != nil {
		// If the config file doesn't exist, use SafeWriteConfig
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return v.SafeWriteConfig()
		}
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	cfg := &Config{
		SocketPath: "/var/run/applock-daemon.sock",
		Verbose:    false,
		Auth: AuthConfig{
			GuiType:               "gtk",
			HashAlgorithm:         "argon2id",
			MaxAttempts:           3,
			LockoutDuration:       300, // 5 minutes
			UseZeroKnowledgeProof: true,
			SecretPath:            "/etc/applock-go/secret",
		},
		Monitor: MonitorConfig{
			ScanInterval:  1,
			ProtectedApps: []string{},
			VerifyHashes:  false,
			HashAlgorithm: "sha256",
		},
	}

	return cfg
}
