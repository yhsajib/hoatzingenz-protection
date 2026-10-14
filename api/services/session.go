package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ResolveClientMAC resolves the MAC address for a client IP using ARP table, host interface, or device fingerprinting
func ResolveClientMAC(clientIP string, userAgent string, headerMAC string) string {
	if headerMAC != "" {
		clean := strings.ToUpper(strings.TrimSpace(headerMAC))
		if len(clean) == 17 || len(clean) == 12 {
			return clean
		}
	}

	cleanIP := strings.TrimSpace(clientIP)
	if h, _, err := net.SplitHostPort(cleanIP); err == nil {
		cleanIP = h
	}

	// 1. ARP Table check (/proc/net/arp)
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				arpIP := fields[0]
				arpMAC := strings.ToUpper(fields[3])
				if arpIP == cleanIP && arpMAC != "00:00:00:00:00:00" && len(arpMAC) == 17 {
					return arpMAC
				}
			}
		}
	}

	// 2. Loopback / Localhost -> Return host primary non-loopback network interface MAC
	if cleanIP == "127.0.0.1" || cleanIP == "localhost" || cleanIP == "::1" || cleanIP == "" {
		if ifaces, err := net.Interfaces(); err == nil {
			for _, iface := range ifaces {
				if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) == 6 {
					mac := strings.ToUpper(iface.HardwareAddr.String())
					if mac != "" && mac != "00:00:00:00:00:00" {
						return mac
					}
				}
			}
		}
	}

	// 3. Check if IP matches any local interface
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if strings.Contains(addr.String(), cleanIP) && len(iface.HardwareAddr) == 6 {
					return strings.ToUpper(iface.HardwareAddr.String())
				}
			}
		}
	}

	// 4. Deterministic Locally-Administered Unicast MAC (02:xx:xx:xx:xx:xx)
	hash := sha256.Sum256([]byte(cleanIP + "::" + userAgent))
	b0 := (hash[0] | 0x02) & 0xFE
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b0, hash[1], hash[2], hash[3], hash[4], hash[5])
}

// ParseDeviceInfo extracts human-readable device and browser name from User-Agent
func ParseDeviceInfo(ua string) string {
	if ua == "" {
		return "Management Console · Browser"
	}

	osName := "Linux"
	switch {
	case strings.Contains(ua, "Windows NT 10.0") || strings.Contains(ua, "Windows NT 11.0"):
		osName = "Windows 11"
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		osName = "macOS"
	case strings.Contains(ua, "iPhone"):
		osName = "iOS · iPhone"
	case strings.Contains(ua, "iPad"):
		osName = "iPadOS"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "Ubuntu"):
		osName = "Ubuntu Linux"
	}

	browser := "Web Browser"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		browser = "Safari"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "curl"):
		browser = "cURL"
	case strings.Contains(ua, "Postman"):
		browser = "Postman"
	case strings.Contains(ua, "Python"):
		browser = "Python SDK"
	}

	return fmt.Sprintf("%s · %s", osName, browser)
}

// HashToken returns SHA-256 hex string of a token
func HashToken(token string) string {
	if token == "" {
		return ""
	}
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// FormatRelativeTime returns human-readable duration string
func FormatRelativeTime(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	diff := time.Since(t)
	if diff < time.Minute {
		return "Just now"
	}
	if diff < time.Hour {
		mins := int(diff.Minutes())
		if mins <= 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d mins ago", mins)
	}
	if diff < 24*time.Hour {
		hrs := int(diff.Hours())
		if hrs <= 1 {
			return "1 hr ago"
		}
		return fmt.Sprintf("%d hrs ago", hrs)
	}
	days := int(diff.Hours() / 24)
	if days <= 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}
