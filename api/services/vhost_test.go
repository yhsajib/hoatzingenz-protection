package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hoatzingenz-protection/api/models"
)

func TestVHostAutomationEngine(t *testing.T) {
	tempDir := t.TempDir()
	availDir := filepath.Join(tempDir, "sites-available")
	enabledDir := filepath.Join(tempDir, "sites-enabled")
	fpmDir := filepath.Join(tempDir, "fpm-pools")

	_ = os.MkdirAll(availDir, 0755)
	_ = os.MkdirAll(enabledDir, 0755)
	_ = os.MkdirAll(fpmDir, 0755)

	engine := NewVHostAutomationEngine(availDir, enabledDir, fpmDir)
	engine.DryRun = false // Test actual writing in temp directory

	site := models.Website{
		DomainName:   "example.org",
		DocumentRoot: filepath.Join(tempDir, "example.org"),
		PHPVersion:   "8.3",
		SiteType:     "wordpress",
		SSLEnabled:   true,
	}

	err := engine.ProvisionWebsite(site)
	if err != nil {
		t.Fatalf("Failed to provision website: %v", err)
	}

	// Verify Nginx Available file
	vhostPath := filepath.Join(availDir, "example.org.conf")
	content, err := os.ReadFile(vhostPath)
	if err != nil {
		t.Fatalf("VHost file was not created: %v", err)
	}

	if !strings.Contains(string(content), "server_name example.org www.example.org;") {
		t.Errorf("VHost content missing server_name")
	}
	if !strings.Contains(string(content), "fastcgi_pass unix:/run/php/php8.3-fpm-example.org.sock;") {
		t.Errorf("VHost content missing FPM socket definition")
	}

	// Verify FPM Pool file
	fpmPath := filepath.Join(fpmDir, "example.org.conf")
	fpmContent, err := os.ReadFile(fpmPath)
	if err != nil {
		t.Fatalf("FPM pool file was not created: %v", err)
	}
	if !strings.Contains(string(fpmContent), "[example.org]") {
		t.Errorf("FPM pool content missing pool header")
	}

	// Test Deprovision
	err = engine.DeprovisionWebsite("example.org")
	if err != nil {
		t.Fatalf("Failed to deprovision website: %v", err)
	}

	if _, err := os.Stat(vhostPath); !os.IsNotExist(err) {
		t.Errorf("VHost file was not removed during deprovision")
	}
}
