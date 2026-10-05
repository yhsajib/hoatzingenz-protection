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
}
