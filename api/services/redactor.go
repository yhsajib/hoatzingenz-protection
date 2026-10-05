package services

import (
	"regexp"
)

var (
	passwordRegex = regexp.MustCompile(`(?i)("(?:password|pass|pwd|secret|auth_token|api_key)"\s*:\s*")([^"]+)(")`)
	bearerRegex   = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*`)
	cookieRegex   = regexp.MustCompile(`(?i)(PHPSESSID|laravel_session|session_id)=[^;]+`)
)

// RedactSecrets scrubs sensitive key-value pairs and authorization credentials from string payloads
func RedactSecrets(input string) string {
	if input == "" {
		return input
	}
	res := passwordRegex.ReplaceAllString(input, `${1}[REDACTED]${3}`)
	res = bearerRegex.ReplaceAllString(res, "${1}[REDACTED]")
	res = cookieRegex.ReplaceAllString(res, "${1}=[REDACTED]")
	return res
}
