package services

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"hoatzingenz-protection/api/models"
)

func GenerateWAFNginxSnippet(cfg models.SiteSecurityConfig) string {
	var sb strings.Builder
	sb.WriteString("\n    # HoatzinGenz Protection WAF & Hardening Rules\n")

	if cfg.BlockSQLi {
		sb.WriteString(`    # Block SQL Injection Patterns
    if ($query_string ~* "(eval\(|select.*from|insert.*into|union.*select|concat\(|drop.*table|benchmark\(|sleep\()") {
        return 403;
    }
`)
	}

	if cfg.BlockXSS {
		sb.WriteString(`    # Block Cross-Site Scripting (XSS) Patterns
    if ($query_string ~* "(<script|javascript:|onerror=|onload=|eval\()") {
        return 403;
    }
`)
	}

	if cfg.HotlinkProtection {
		sb.WriteString(fmt.Sprintf(`    # Hotlink Protection
    location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
        valid_referers none blocked server_names ~\.google\. ~\.bing\.;
        if ($invalid_referer) {
            return 403;
        }
    }
`, cfg.DomainName))
	}

	if len(cfg.BlockedIPs) > 0 {
		sb.WriteString("\n    # Blacklisted IP Addresses\n")
		for _, ip := range cfg.BlockedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				sb.WriteString(fmt.Sprintf("    deny %s;\n", ip))
			}
		}
	}

	if len(cfg.AllowedIPs) > 0 {
		sb.WriteString("\n    # Whitelisted IP Addresses\n")
		for _, ip := range cfg.AllowedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				sb.WriteString(fmt.Sprintf("    allow %s;\n", ip))
			}
		}
	}

	return sb.String()
}

func BanIPOnHost(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip address required")
	}

	if fail2banClient, err := exec.LookPath("fail2ban-client"); err == nil {
		out, err := exec.Command(fail2banClient, "set", "nginx-http-auth", "banip", ip).CombinedOutput()
		if err == nil {
			log.Printf("[SECURITY] Fail2Ban banned IP %s: %s", ip, string(out))
			return nil
		}
	}

	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command(ufwPath, "deny", "from", ip).Run()
		log.Printf("[SECURITY] UFW banned IP %s", ip)
		return nil
	}

	if iptablesPath, err := exec.LookPath("iptables"); err == nil {
		_ = exec.Command(iptablesPath, "-A", "INPUT", "-s", ip, "-j", "DROP").Run()
		log.Printf("[SECURITY] IPTables banned IP %s", ip)
		return nil
	}

	log.Printf("[SECURITY WARN] Simulated IP ban for %s (no fail2ban/ufw/iptables binary)", ip)
	return nil
}

func UnbanIPOnHost(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip address required")
	}

	if fail2banClient, err := exec.LookPath("fail2ban-client"); err == nil {
		_ = exec.Command(fail2banClient, "set", "nginx-http-auth", "unbanip", ip).Run()
	}

	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command(ufwPath, "delete", "deny", "from", ip).Run()
	}

	if iptablesPath, err := exec.LookPath("iptables"); err == nil {
		_ = exec.Command(iptablesPath, "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	}

	return nil
}

func SyncFail2BanJails() error {
	jailPath := "/etc/fail2ban/jail.d/hoatzin.conf"
	if _, err := os.Stat("/etc/fail2ban"); os.IsNotExist(err) {
		return nil
	}

	content := `[hoatzin-nginx-sqli]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/*error.log
maxretry = 5
findtime = 600
bantime  = 3600
`
	_ = os.WriteFile(jailPath, []byte(content), 0644)
	if fail2banClient, err := exec.LookPath("fail2ban-client"); err == nil {
		_ = exec.Command(fail2banClient, "reload").Run()
	}
	return nil
}
