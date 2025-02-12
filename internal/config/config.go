package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration settings
type Config struct {
	API      APIConfig
	Database DatabaseConfig
	App      AppConfig
}

// APIConfig holds API-related configuration
type APIConfig struct {
	BaseURL        string
	ApplicationKey string
	Timeout        time.Duration
	MaxRetries     int
	RetryDelay     time.Duration
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
	Path           string
	MaxConnections int
}

// AppConfig holds application-specific configuration
type AppConfig struct {
	Environment     string
	LogLevel        string
	WorkerCount     int
	BatchSize       int
	ShutdownTimeout time.Duration
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// Only return error if file exists but couldn't be loaded
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading .env file: %w", err)
		}
	}

	cfg := &Config{}

	// Load API configuration
	cfg.API = APIConfig{
		BaseURL:        getEnv("API_BASE_URL", "https://api.lookout.com"),
		ApplicationKey: getEnv("APPLICATION_KEY", ""), // Make it optional
		Timeout:        getDurationEnv("API_TIMEOUT", 30*time.Second),
		MaxRetries:     getIntEnv("API_MAX_RETRIES", 3),
		RetryDelay:     getDurationEnv("API_RETRY_DELAY", 5*time.Second),
	}

	// Load database configuration
	cfg.Database = DatabaseConfig{
		Path:           getEnv("DB_PATH", filepath.Join("data", "devices.db")),
		MaxConnections: getIntEnv("DB_MAX_CONNECTIONS", 10),
	}

	// Load application configuration
	cfg.App = AppConfig{
		Environment:     getEnv("APP_ENV", "development"),
		LogLevel:        getEnv("LOG_LEVEL", "info"),
		WorkerCount:     getIntEnv("WORKER_COUNT", 5),
		BatchSize:       getIntEnv("BATCH_SIZE", 1000),
		ShutdownTimeout: getDurationEnv("SHUTDOWN_TIMEOUT", 30*time.Second),
	}

	// Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return cfg, nil
}

// validate performs configuration validation
func (c *Config) validate() error {
	// Validate API configuration
	isLocalMode := len(os.Args) > 1 && os.Args[1] == "--local"
	if !isLocalMode && c.API.ApplicationKey == "" {
		return fmt.Errorf("APPLICATION_KEY is required when not in local mode")
	}
	if c.API.Timeout < 1*time.Second {
		return fmt.Errorf("API_TIMEOUT must be at least 1 second")
	}
	if c.API.MaxRetries < 0 {
		return fmt.Errorf("API_MAX_RETRIES must be non-negative")
	}
	if c.API.RetryDelay < 1*time.Second {
		return fmt.Errorf("API_RETRY_DELAY must be at least 1 second")
	}

	// Validate database configuration
	if c.Database.Path == "" {
		return fmt.Errorf("DB_PATH is required")
	}
	if c.Database.MaxConnections < 1 {
		return fmt.Errorf("DB_MAX_CONNECTIONS must be at least 1")
	}

	// Validate application configuration
	if !isValidEnvironment(c.App.Environment) {
		return fmt.Errorf("invalid APP_ENV: %s", c.App.Environment)
	}
	if !isValidLogLevel(c.App.LogLevel) {
		return fmt.Errorf("invalid LOG_LEVEL: %s", c.App.LogLevel)
	}
	if c.App.WorkerCount < 1 {
		return fmt.Errorf("WORKER_COUNT must be at least 1")
	}
	if c.App.BatchSize < 1 {
		return fmt.Errorf("BATCH_SIZE must be at least 1")
	}
	if c.App.ShutdownTimeout < 1*time.Second {
		return fmt.Errorf("SHUTDOWN_TIMEOUT must be at least 1 second")
	}

	return nil
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func requireEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return value
}

func getIntEnv(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func isValidEnvironment(env string) bool {
	validEnvs := map[string]bool{
		"development": true,
		"testing":     true,
		"staging":     true,
		"production":  true,
	}
	return validEnvs[env]
}

func isValidLogLevel(level string) bool {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
		"fatal": true,
	}
	return validLevels[level]
}
