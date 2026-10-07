package services

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hoatzingenz-protection/api/models"
)

func (v *VHostAutomationEngine) CloneWebsite(srcSite models.Website, targetDomain string) (*models.Website, error) {
	targetDomain = strings.ToLower(strings.TrimSpace(targetDomain))
	if !ValidDomain(targetDomain) {
		return nil, fmt.Errorf("invalid target domain name")
	}

	srcRoot := SiteRootDir(srcSite.DomainName)
	if _, err := os.Stat(srcRoot); os.IsNotExist(err) {
		localFallback := filepath.Join("./data/sites", srcSite.DomainName)
		if _, err2 := os.Stat(localFallback); err2 == nil {
			srcRoot = localFallback
		} else {
			return nil, fmt.Errorf("source site document root for %s not found", srcSite.DomainName)
		}
	}

	targetRoot := SiteRootDir(targetDomain)
	if err := os.MkdirAll(targetRoot, 0755); err != nil {
		return nil, fmt.Errorf("failed to create target document root: %w", err)
	}

	// 1. Copy site files
	log.Printf("[CLONE] Copying files from %s to %s", srcRoot, targetRoot)
	if err := copyDirContents(srcRoot, targetRoot); err != nil {
		log.Printf("[CLONE WARN] Copy files warning: %v", err)
	}

	targetSite := models.Website{
		DomainName:   targetDomain,
		PHPVersion:   srcSite.PHPVersion,
		SiteType:     srcSite.SiteType,
		AppPort:      srcSite.AppPort + 1,
		SSLEnabled:   false,
		ForceHTTPS:   false,
		Status:       "active",
		TrackingID:   "HZ-SITE-" + RandomString(8),
		SiteTitle:    srcSite.SiteTitle + " (Staging)",
		DocumentRoot: targetRoot,
		CreatedAt:    time.Now(),
	}

	// 2. Clone database if source site has DB
	if srcSite.DBName != "" {
		targetDBName := "db_" + strings.ReplaceAll(strings.ReplaceAll(targetDomain, ".", "_"), "-", "_")
		if len(targetDBName) > 32 {
			targetDBName = targetDBName[:32]
		}
		targetDBUser := "usr_" + RandomString(8)
		targetDBPass := RandomString(16)

		log.Printf("[CLONE] Creating target database %s for %s", targetDBName, targetDomain)
		if err := v.MySQLCreate(targetDBName, targetDBUser, targetDBPass); err == nil {
			targetSite.DBName = targetDBName
			targetSite.DBUser = targetDBUser
			targetSite.DBPass = targetDBPass
			targetSite.DBHost = "localhost"

			// Export source DB and import into target DB
			if sqlDump, err := v.MySQLDump(srcSite.DBName); err == nil && len(sqlDump) > 0 {
				// Replace source domain with target domain in SQL dump
				sqlText := strings.ReplaceAll(string(sqlDump), srcSite.DomainName, targetDomain)
				_ = v.MySQLRestore(targetDBName, sqlText)
				log.Printf("[CLONE SUCCESS] Restored database dump into %s", targetDBName)
			}
		}
	}

	// 3. Update configuration files (wp-config.php or .env) in target directory
	if targetSite.SiteType == "wordpress" {
		_ = WriteWPConfig(targetRoot, targetSite)
	} else if targetSite.SiteType == "laravel" {
		envPath := filepath.Join(targetRoot, ".env")
		if _, err := os.Stat(envPath); err == nil {
			envContent := v.GenerateEnvConfig(targetSite)
			_ = os.WriteFile(envPath, []byte(envContent), 0644)
		}
	}

	// 4. Provision virtual host in Nginx & PHP-FPM
	if err := v.ProvisionWebsite(targetSite); err != nil {
		log.Printf("[CLONE WARN] VHost provision warning for %s: %v", targetDomain, err)
	}

	log.Printf("[CLONE SUCCESS] Website %s successfully cloned to %s!", srcSite.DomainName, targetDomain)
	return &targetSite, nil
}

func copyDirContents(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		targetPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer srcFile.Close()

		dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return nil
		}
		defer dstFile.Close()

		_, _ = io.Copy(dstFile, srcFile)
		return nil
	})
}
