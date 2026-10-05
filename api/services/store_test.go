package services

import (
	"os"
	"testing"
	"time"

	"hoatzingenz-protection/api/models"
)

func TestSecretRedactor(t *testing.T) {
	input := `{"user": "admin", "password": "supersecretpassword123", "token": "Bearer eyJhbGciOi..."}`
	redacted := RedactSecrets(input)

	if redacted == input {
		t.Errorf("Expected secrets to be redacted, got unchanged: %s", redacted)
	}
	if testing.Verbose() {
		t.Logf("Redacted output: %s", redacted)
	}
}

func TestJWTAuth(t *testing.T) {
	user := models.User{
		ID:        1,
		Username:  "testadmin",
		Role:      "admin",
		CreatedAt: time.Now(),
	}

	token, exp, err := GenerateToken(user, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	if token == "" {
		t.Fatal("Generated token is empty")
	}
	if exp.Before(time.Now()) {
		t.Fatal("Token expiration is invalid")
	}

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if claims.Username != "testadmin" || claims.Role != "admin" {
		t.Errorf("Mismatch in token claims: %+v", claims)
	}
}

func TestDBStore(t *testing.T) {
	dbPath := "./test_controlpanel.db"
	defer os.Remove(dbPath)

	store, err := NewDBStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create DBStore: %v", err)
	}
	defer store.Close()

	// Test default admin user seed
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("Default admin user not found: %v", err)
	}
	if user.PasswordHash != HashPassword("admin123") {
		t.Errorf("Admin password hash mismatch")
	}

	// Test Website CRUD
	site := store.AddWebsite(models.Website{
		TeamID:       1,
		DomainName:   "testsite.com",
		DocumentRoot: "/var/www/testsite.com",
		PHPVersion:   "8.3",
		SiteType:     "wordpress",
		SSLEnabled:   true,
		SSLProvider:  "letsencrypt",
		Status:       "active",
	})
	if site.ID == 0 {
		t.Errorf("Failed to insert website")
	}

	sites := store.GetWebsites()
	if len(sites) == 0 {
		t.Errorf("Expected websites in DB, got 0")
	}

	// Test Security Event recording with Redaction
	event := store.RecordSecurityEvent(models.SecurityEvent{
		EventType:     "WEBSHELL_DETECTED",
		Severity:      "critical",
		Source:        "go-agent",
		TargetPath:    "/var/www/uploads/shell.php",
		Payload:       `{"password": "stolenpassword123"}`,
		IsQuarantined: true,
	})
	if event.ID == 0 {
		t.Errorf("Failed to record security event")
	}

	events := store.GetSecurityEvents()
	if len(events) == 0 {
		t.Errorf("Expected security events in DB, got 0")
	}
}
