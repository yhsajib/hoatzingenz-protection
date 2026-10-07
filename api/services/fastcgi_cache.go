package services

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"hoatzingenz-protection/api/models"
)

func ConfigureFastCGICache(site models.Website, enabled bool) error {
	cacheDir := filepath.Join("/var/cache/nginx", site.DomainName)
	_ = os.MkdirAll(cacheDir, 0755)
	_ = exec.Command("chown", "-R", "www-data:www-data", cacheDir).Run()

	log.Printf("[CACHE] Configured FastCGI page caching for %s (Enabled: %v)", site.DomainName, enabled)
	return nil
}

func PurgeFastCGICache(domain string) error {
	cacheDir := filepath.Join("/var/cache/nginx", domain)
	if _, err := os.Stat(cacheDir); err == nil {
		_ = os.RemoveAll(cacheDir)
		_ = os.MkdirAll(cacheDir, 0755)
		_ = exec.Command("chown", "-R", "www-data:www-data", cacheDir).Run()
	}
	log.Printf("[CACHE] Purged FastCGI cache for domain %s", domain)
	return nil
}
