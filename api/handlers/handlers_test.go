package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"hoatzingenz-protection/api/models"
	"hoatzingenz-protection/api/services"
)

func TestAPIHandlersWithDBStore(t *testing.T) {
	dbPath := "./test_handlers.db"
	defer os.Remove(dbPath)

	dbStore, err := services.NewDBStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize test db: %v", err)
	}
	defer dbStore.Close()

	memStore := services.NewMemoryStore()
	h := NewAPIHandler(memStore, dbStore, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", h.HealthCheck)
	mux.HandleFunc("/api/v1/auth/login", h.HandleLogin)
	mux.HandleFunc("/api/v1/websites", h.AuthMiddleware(h.HandleWebsites))
	mux.HandleFunc("/api/v1/website/action", h.AuthMiddleware(h.HandleWebsiteActions))
	mux.HandleFunc("/api/v1/databases/export-all", h.AuthMiddleware(h.HandleExportAllDatabases))
	mux.HandleFunc("/api/v1/database/change-password", h.AuthMiddleware(h.HandleDatabaseChangePassword))
	mux.HandleFunc("/api/v1/security/telemetry", h.AuthMiddleware(h.HandleSecurityTelemetry))

	handler := SecurityHeadersMiddleware(mux)

	// 1. Test Health Check
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// 2. Test Login (Success)
	loginBody, _ := json.Marshal(models.AuthRequest{
		Username: "admin",
		Password: "admin123",
	})
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(loginBody))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Login failed, expected 200, got %d", rr.Code)
	}

	var authResp models.AuthResponse
	json.NewDecoder(rr.Body).Decode(&authResp)
	if authResp.Token == "" {
		t.Fatalf("Expected token in login response")
	}

	// 3. Test Protected Endpoint Without Token (Failure)
	req = httptest.NewRequest("GET", "/api/v1/websites", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for unauthenticated request, got %d", rr.Code)
	}

	// 4. Test Protected Endpoint With Token (Success)
	req = httptest.NewRequest("GET", "/api/v1/websites", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for authenticated request, got %d", rr.Code)
	}

	// 5. Test Telemetry Endpoint with X-Agent-Key
	req = httptest.NewRequest("GET", "/api/v1/security/telemetry", nil)
	req.Header.Set("X-Agent-Key", "hz_agent_secret_key_2026")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for agent key authenticated request, got %d", rr.Code)
	}

	// Insert a test website directly so activation/deactivation can be tested
	dbStore.AddWebsite(models.Website{
		DomainName:   "test-domain.org",
		DocumentRoot: "/var/www/html/test-domain.org",
		SiteType:     "static",
		Status:       "active",
	})

	// 6. Test Deactivating Website via /api/v1/website/action
	deactBody, _ := json.Marshal(map[string]string{
		"domain": "test-domain.org",
		"action": "deactivate",
	})
	req = httptest.NewRequest("POST", "/api/v1/website/action", bytes.NewBuffer(deactBody))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for deactivate action, got %d", rr.Code)
	}

	site, err := dbStore.GetWebsiteByDomain("test-domain.org")
	if err != nil || site.Status != "suspended" {
		t.Errorf("Expected site status 'suspended' after deactivate, got '%s', err: %v", site.Status, err)
	}

	// 7. Test Activating Website via /api/v1/website/action
	actBody, _ := json.Marshal(map[string]string{
		"domain": "test-domain.org",
		"action": "activate",
	})
	req = httptest.NewRequest("POST", "/api/v1/website/action", bytes.NewBuffer(actBody))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for activate action, got %d", rr.Code)
	}

	site, err = dbStore.GetWebsiteByDomain("test-domain.org")
	if err != nil || site.Status != "active" {
		t.Errorf("Expected site status 'active' after activate, got '%s', err: %v", site.Status, err)
	}

	// Insert a test database directly so export and password update can be tested
	_ = dbStore.AddDatabase(models.ServerDatabase{
		Name:     "test_db",
		Engine:   "mysql",
		Username: "test_user",
		Password: "InitialPass123!",
		Host:     "127.0.0.1",
		Port:     3306,
		Status:   "active",
	})

	// 8. Test Export All Databases (ZIP format)
	req = httptest.NewRequest("GET", "/api/v1/databases/export-all?format=zip", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for export-all zip, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Expected Content-Type application/zip, got %s", ct)
	}

	// 9. Test Export All Databases (SQL format)
	req = httptest.NewRequest("GET", "/api/v1/databases/export-all?format=sql", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for export-all sql, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/sql" {
		t.Errorf("Expected Content-Type application/sql, got %s", ct)
	}

	// 10. Test Database Password Change by SuperAdmin
	pwBody, _ := json.Marshal(map[string]string{
		"name":     "test_db",
		"password": "SuperSecretPass2026!",
	})
	req = httptest.NewRequest("POST", "/api/v1/database/change-password", bytes.NewBuffer(pwBody))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for change-password, got %d, body: %s", rr.Code, rr.Body.String())
	}

	updatedDb, err := dbStore.GetDatabaseByName("test_db")
	if err != nil || updatedDb.Password != "SuperSecretPass2026!" {
		t.Errorf("Expected updated password 'SuperSecretPass2026!', got '%s', err: %v", updatedDb.Password, err)
	}
}
