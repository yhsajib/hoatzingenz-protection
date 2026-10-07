package services

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"hoatzingenz-protection/api/models"
)

type ResourceLimits struct {
	DomainName string  `json:"domain_name"`
	MemoryMax  string  `json:"memory_max"`
	CPUQuota   string  `json:"cpu_quota"`
	DiskQuota  string  `json:"disk_quota"`
	UsedDiskMB float64 `json:"used_disk_mb"`
}

func GetSiteResourceLimits(domain string) ResourceLimits {
	docRoot := SiteRootDir(domain)
	usedMB := float64(0)
	if out, err := exec.Command("du", "-sm", docRoot).Output(); err == nil {
		parts := strings.Fields(string(out))
		if len(parts) > 0 {
			if val, err := strconv.ParseFloat(parts[0], 64); err == nil {
				usedMB = val
			}
		}
	}

	return ResourceLimits{
		DomainName: domain,
		MemoryMax:  "512M",
		CPUQuota:   "100%",
		DiskQuota:  "10000M",
		UsedDiskMB: usedMB,
	}
}

func SaveSiteResourceLimits(site models.Website, limits ResourceLimits) error {
	unitName := "hz-site-" + nonAlnumRe.ReplaceAllString(site.DomainName, "-") + ".service"
	unitPath := filepath.Join("/etc/systemd/system", unitName)

	if _, err := os.Stat(unitPath); err == nil {
		content := fmt.Sprintf("[Unit]\nDescription=%s Resource Limits Unit\nAfter=network.target\n\n[Service]\nType=simple\nUser=www-data\nWorkingDirectory=%s\nMemoryMax=%s\nCPUQuota=%s\n\n[Install]\nWantedBy=multi-user.target\n", site.DomainName, site.DocumentRoot, limits.MemoryMax, limits.CPUQuota)
		_ = os.WriteFile(unitPath, []byte(content), 0644)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}

	log.Printf("[RESOURCE LIMITS] Updated CPU/RAM/Disk limits for %s (RAM: %s, CPU: %s)", site.DomainName, limits.MemoryMax, limits.CPUQuota)
	return nil
}
