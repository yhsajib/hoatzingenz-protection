package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"hoatzingenz-protection/api/models"
	"hoatzingenz-protection/api/services"
)

// UserProfile holds editable, non-credential profile fields and UI preferences.
type UserProfile struct {
	DisplayName     string `json:"display_name"`
	Email           string `json:"email"`
	Phone           string `json:"phone"`
	Company         string `json:"company"`
	JobTitle        string `json:"job_title"`
	Timezone        string `json:"timezone"`
	Language        string `json:"language"`
	DateFormat      string `json:"date_format"`
	AutoLogout      string `json:"auto_logout"`
	NotifyIncidents bool   `json:"notify_incidents"`
	NotifyBackups   bool   `json:"notify_backups"`
	NotifyLogins    bool   `json:"notify_logins"`
	NotifyDigest    bool   `json:"notify_digest"`
}

func defaultUserProfile(username string) UserProfile {
	return UserProfile{
		DisplayName:     username,
		Timezone:        "UTC",
		Language:        "English (US)",
		DateFormat:      "YYYY-MM-DD",
		AutoLogout:      "30m",
		NotifyIncidents: true,
		NotifyBackups:   true,
		NotifyLogins:    true,
		NotifyDigest:    false,
	}
}

var allowedAutoLogout = map[string]bool{"15m": true, "30m": true, "1h": true, "4h": true, "Never": true}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// currentUser resolves the JWT-authenticated user. API-key callers have no user identity.
func (h *APIHandler) currentUser(r *http.Request) (*models.User, int, string) {
	claims, ok := r.Context().Value(UserContextKey).(*services.JWTClaims)
	if !ok || claims == nil {
		return nil, http.StatusUnauthorized, "Profile endpoints require an interactive (JWT) session"
	}
	if h.DBStore == nil {
		return nil, http.StatusServiceUnavailable, "Database store unavailable"
	}
	user, err := h.DBStore.GetUserByUsername(claims.Username)
	if err != nil || user == nil {
		return nil, http.StatusNotFound, "User account not found"
	}
	return user, 0, ""
}

// HandleProfile: GET returns account + saved profile; PUT saves profile fields.
func (h *APIHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {
	user, code, msg := h.currentUser(r)
	if user == nil {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}

	switch r.Method {
	case http.MethodGet:
		profile := defaultUserProfile(user.Username)
		raw, updatedAt, err := h.DBStore.GetUserProfile(user.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to load profile: " + err.Error()})
			return
		}
		_ = json.Unmarshal([]byte(raw), &profile)

		resp := map[string]interface{}{
			"account": map[string]interface{}{
				"id":                 user.ID,
				"username":           user.Username,
				"role":               user.Role,
				"two_factor_enabled": user.TwoFactorEnabled,
				"created_at":         user.CreatedAt,
			},
			"profile":     profile,
			"server_time": time.Now().Format(time.RFC3339),
		}
		if !updatedAt.IsZero() {
			resp["updated_at"] = updatedAt
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPut, http.MethodPost:
		var p UserProfile
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid profile payload"})
			return
		}
		p.DisplayName = clip(p.DisplayName, 120)
		p.Email = clip(p.Email, 254)
		p.Phone = clip(p.Phone, 40)
		p.Company = clip(p.Company, 160)
		p.JobTitle = clip(p.JobTitle, 120)
		p.Timezone = clip(p.Timezone, 80)
		p.Language = clip(p.Language, 40)
		p.DateFormat = clip(p.DateFormat, 20)

		if p.Email != "" {
			if _, err := mail.ParseAddress(p.Email); err != nil {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "Email address is not valid"})
				return
			}
		}
		if !allowedAutoLogout[p.AutoLogout] {
			p.AutoLogout = "30m"
		}

		b, _ := json.Marshal(p)
		if err := h.DBStore.SaveUserProfile(user.ID, string(b)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save profile: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "profile": p})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
	}
}

// HandleProfilePassword verifies the current password and stores a new bcrypt hash.
func (h *APIHandler) HandleProfilePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	user, code, msg := h.currentUser(r)
	if user == nil {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	clientIP := services.GetClientIP(r)
	if !services.CheckPasswordHash(req.CurrentPassword, user.PasswordHash) {
		time.Sleep(300 * time.Millisecond)
		h.DBStore.RecordSecurityEvent(models.SecurityEvent{
			EventType:  "PASSWORD_CHANGE_FAILED",
			Severity:   "medium",
			Source:     "auth-guard",
			Payload:    fmt.Sprintf("Wrong current password supplied for '%s' from IP %s", user.Username, clientIP),
			TargetPath: "/api/v1/profile/password",
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Current password is incorrect"})
		return
	}
	if len(req.NewPassword) < 10 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "New password must be at least 10 characters"})
		return
	}
	if len(req.NewPassword) > 72 {
		// bcrypt silently truncates beyond 72 bytes
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "New password must be at most 72 characters"})
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "New password must differ from the current password"})
		return
	}

	hash, err := services.HashPassword(req.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
		return
	}
	if err := h.DBStore.UpdateUserPassword(user.Username, hash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update password: " + err.Error()})
		return
	}

	h.DBStore.RecordSecurityEvent(models.SecurityEvent{
		EventType:  "ADMIN_PASSWORD_CHANGED",
		Severity:   "info",
		Source:     "auth-guard",
		Payload:    fmt.Sprintf("Administrator '%s' changed their panel password from IP %s", user.Username, clientIP),
		TargetPath: "/api/v1/profile/password",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Password updated"})
}
