package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"hoatzingenz-protection/api/models"
)

var (
	jwtSecretMu sync.RWMutex
	jwtSecret   = []byte("hz_jwt_secret_key_protection_2026_super_secure")
)

// InitJWTSecret initializes a persistent, cryptographically secure 256-bit JWT secret.
func InitJWTSecret(dbDir string) {
	jwtSecretMu.Lock()
	defer jwtSecretMu.Unlock()

	// 1. Environment variable override
	if envSec := os.Getenv("HZ_JWT_SECRET"); len(envSec) >= 32 {
		jwtSecret = []byte(envSec)
		return
	}

	// 2. Secret file on disk
	if dbDir != "" {
		_ = os.MkdirAll(dbDir, 0700)
		keyFile := filepath.Join(dbDir, "jwt_secret.key")
		if data, err := os.ReadFile(keyFile); err == nil && len(data) >= 32 {
			jwtSecret = data
			return
		}

		// 3. Generate 32 secure random bytes
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err == nil {
			_ = os.WriteFile(keyFile, buf, 0600)
			jwtSecret = buf
			return
		}
	}
}

func getJWTSecret() []byte {
	jwtSecretMu.RLock()
	defer jwtSecretMu.RUnlock()
	return jwtSecret
}

type JWTClaims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"sub"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

func GenerateToken(user models.User, duration time.Duration) (string, time.Time, error) {
	expTime := time.Now().Add(duration)
	claims := JWTClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Exp:      expTime.Unix(),
		Iat:      time.Now().Unix(),
	}

	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := headerB64 + "." + claimsB64

	h := hmac.New(sha256.New, getJWTSecret())
	h.Write([]byte(unsignedToken))
	sigB64 := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	token := unsignedToken + "." + sigB64
	return token, expTime, nil
}

func ValidateToken(tokenStr string) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	unsignedToken := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, getJWTSecret())
	h.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Constant time comparison to prevent timing side-channel attacks
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return nil, fmt.Errorf("invalid token signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload")
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims")
	}

	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token has expired")
	}

	return &claims, nil
}

// ---------------------------------------------------------------------------
// Bcrypt & Password Management
// ---------------------------------------------------------------------------

// HashPassword hashes a plain text password using Bcrypt (cost 12).
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPasswordHash verifies a plain text password against a bcrypt or legacy sha256 hash.
func CheckPasswordHash(password, hash string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}

	// Legacy SHA256 fallback with constant-time comparison
	hasher := sha256.New()
	hasher.Write([]byte(password + "_hoatzin_salt_2026"))
	legacyHash := hex.EncodeToString(hasher.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(hash), []byte(legacyHash)) == 1
}

// ValidatePasswordStrength enforces strong passwords (>= 8 chars, uppercase, lowercase, number).
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, and one number")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 2FA TOTP (RFC 6238) Implementation
// ---------------------------------------------------------------------------

func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func GenerateTOTPCode(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := (uint32(hash[offset]&0x7f)<<24 | uint32(hash[offset+1])<<16 | uint32(hash[offset+2])<<8 | uint32(hash[offset+3])) % 1000000
	return fmt.Sprintf("%06d", code)
}

func ValidateTOTPCode(secret string, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now()
	for _, dt := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if GenerateTOTPCode(secret, now.Add(dt)) == code {
			return true
		}
	}
	return false
}

func GenerateOTPAuthURL(username string, secret string) string {
	return fmt.Sprintf("otpauth://totp/HoatzinGenz:%s?secret=%s&issuer=HoatzinGenz", username, secret)
}

// ---------------------------------------------------------------------------
// Anti-Brute-Force Rate Limiter & Login Guard
// ---------------------------------------------------------------------------

type LoginRecord struct {
	Failures    int
	FirstFailAt time.Time
	LockedUntil time.Time
}

type LoginSecurityManager struct {
	mu              sync.Mutex
	records         map[string]*LoginRecord
	maxAttempts     int
	window          time.Duration
	lockoutDuration time.Duration
}

func NewLoginSecurityManager(maxAttempts int, window, lockout time.Duration) *LoginSecurityManager {
	return &LoginSecurityManager{
		records:         make(map[string]*LoginRecord),
		maxAttempts:     maxAttempts,
		window:          window,
		lockoutDuration: lockout,
	}
}

// GlobalLoginGuard enforces max 5 failed attempts per IP or username within 15 minutes
var GlobalLoginGuard = NewLoginSecurityManager(5, 15*time.Minute, 15*time.Minute)

func (m *LoginSecurityManager) IsLocked(ip, username string) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, key := range []string{"ip:" + ip, "user:" + strings.ToLower(username)} {
		rec, exists := m.records[key]
		if exists && rec.LockedUntil.After(now) {
			return true, rec.LockedUntil.Sub(now)
		}
	}
	return false, 0
}

func (m *LoginSecurityManager) RecordFailure(ip, username string) (bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	locked := false
	minRemaining := m.maxAttempts

	for _, key := range []string{"ip:" + ip, "user:" + strings.ToLower(username)} {
		rec, exists := m.records[key]
		if !exists || now.Sub(rec.FirstFailAt) > m.window {
			rec = &LoginRecord{
				Failures:    1,
				FirstFailAt: now,
			}
			m.records[key] = rec
		} else {
			rec.Failures++
		}

		if rec.Failures >= m.maxAttempts {
			rec.LockedUntil = now.Add(m.lockoutDuration)
			locked = true
			minRemaining = 0
		} else {
			rem := m.maxAttempts - rec.Failures
			if rem < minRemaining {
				minRemaining = rem
			}
		}
	}

	return locked, minRemaining
}

func (m *LoginSecurityManager) RecordSuccess(ip, username string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.records, "ip:"+ip)
	delete(m.records, "user:"+strings.ToLower(username))
}

func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
