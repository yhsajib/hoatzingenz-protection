package config

import (
	"fmt"
	"os"
)

type Config struct {
	ServerID       string
	Environment    string
	CloudEndpoint  string
	APIKey         string
	SpoolDirectory string
	QuarantineDir  string
	AutoQuarantine bool
	WatchPaths     []string
	WebUsers       []string
}

func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Return baseline defaults if config file is absent
		return &Config{
			ServerID:       "srv_default_01",
			Environment:    "production",
			CloudEndpoint:  "https://api.hoatzingenz-protection.io",
			SpoolDirectory: "/opt/diagnostic-agent/spool",
			QuarantineDir:  "/opt/diagnostic-agent/quarantine",
			AutoQuarantine: false,
			WatchPaths:     []string{"/var/www/html"},
			WebUsers:       []string{"www-data", "nginx", "apache", "nobody"},
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	_ = data
	return &Config{
		ServerID:       "srv_prod_01",
		Environment:    "production",
		CloudEndpoint:  "https://api.hoatzingenz-protection.io",
		SpoolDirectory: "/opt/diagnostic-agent/spool",
		QuarantineDir:  "/opt/diagnostic-agent/quarantine",
		AutoQuarantine: false,
		WatchPaths:     []string{"/var/www/html"},
		WebUsers:       []string{"www-data", "nginx", "apache", "nobody"},
	}, nil
}
