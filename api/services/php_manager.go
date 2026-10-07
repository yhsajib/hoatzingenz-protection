package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"hoatzingenz-protection/api/models"
)

type PHPConfig struct {
	PHPVersion          string          `json:"php_version"`
	MemoryLimit         string          `json:"memory_limit"`
	UploadMaxFilesize   string          `json:"upload_max_filesize"`
	MaxExecutionTime    string          `json:"max_execution_time"`
	PostMaxSize         string          `json:"post_max_size"`
	DisplayErrors       bool            `json:"display_errors"`
	OPcacheEnabled      bool            `json:"opcache_enabled"`
	InstalledExtensions map[string]bool `json:"installed_extensions"`
}

func GetPHPConfig(phpVer string) PHPConfig {
	if phpVer == "" {
		phpVer = "8.3"
	}

	exts := map[string]bool{
		"curl":      true,
		"gd":        true,
		"mbstring":  true,
		"mysqli":    true,
		"pdo_mysql": true,
		"opcache":   true,
		"redis":     true,
		"xml":       true,
		"zip":       true,
		"intl":      true,
		"imagick":   true,
	}

	if phpPath, err := exec.LookPath("php" + phpVer); err == nil {
		out, err := exec.Command(phpPath, "-m").Output()
		if err == nil {
			modStr := strings.ToLower(string(out))
			for k := range exts {
				exts[k] = strings.Contains(modStr, k)
			}
		}
	}

	return PHPConfig{
		PHPVersion:          phpVer,
		MemoryLimit:         "256M",
		UploadMaxFilesize:   "64M",
		MaxExecutionTime:    "300",
		PostMaxSize:         "64M",
		DisplayErrors:       false,
		OPcacheEnabled:      true,
		InstalledExtensions: exts,
	}
}

func SavePHPConfig(site models.Website, cfg PHPConfig) error {
	fpmDir := fmt.Sprintf("/etc/php/%s/fpm/pool.d", site.PHPVersion)
	_ = os.MkdirAll(fpmDir, 0755)

	fpmPath := filepath.Join(fpmDir, site.DomainName+".conf")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s]\n", site.DomainName))
	sb.WriteString("user = www-data\n")
	sb.WriteString("group = www-data\n")
	sb.WriteString(fmt.Sprintf("listen = /run/php/php%s-fpm-%s.sock\n", site.PHPVersion, site.DomainName))
	sb.WriteString("listen.owner = www-data\n")
	sb.WriteString("listen.group = www-data\n")
	sb.WriteString("listen.mode = 0660\n")
	sb.WriteString("pm = dynamic\n")
	sb.WriteString("pm.max_children = 20\n")
	sb.WriteString("pm.start_servers = 2\n")
	sb.WriteString("pm.min_spare_servers = 1\n")
	sb.WriteString("pm.max_spare_servers = 3\n\n")

	if cfg.MemoryLimit != "" {
		sb.WriteString(fmt.Sprintf("php_admin_value[memory_limit] = %s\n", cfg.MemoryLimit))
	}
	if cfg.UploadMaxFilesize != "" {
		sb.WriteString(fmt.Sprintf("php_admin_value[upload_max_filesize] = %s\n", cfg.UploadMaxFilesize))
	}
	if cfg.MaxExecutionTime != "" {
		sb.WriteString(fmt.Sprintf("php_admin_value[max_execution_time] = %s\n", cfg.MaxExecutionTime))
	}
	if cfg.PostMaxSize != "" {
		sb.WriteString(fmt.Sprintf("php_admin_value[post_max_size] = %s\n", cfg.PostMaxSize))
	}
	if cfg.DisplayErrors {
		sb.WriteString("php_flag[display_errors] = on\n")
	} else {
		sb.WriteString("php_flag[display_errors] = off\n")
	}

	_ = os.WriteFile(fpmPath, []byte(sb.String()), 0644)
	_ = exec.Command("systemctl", "reload", "php"+site.PHPVersion+"-fpm").Run()
	return nil
}
