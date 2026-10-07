package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"hoatzingenz-protection/api/models"
)

var jwtSecret = []byte("hz_jwt_secret_key_protection_2026_super_secure")

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

	h := hmac.New(sha256.New, jwtSecret)
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
	h := hmac.New(sha256.New, jwtSecret)
	h.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if parts[2] != expectedSig {
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
// 2FA TOTP (RFC 6238) Implementation
// ---------------------------------------------------------------------------

func GenerateTOTPSecret() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func GenerateTOTPCode(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
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
