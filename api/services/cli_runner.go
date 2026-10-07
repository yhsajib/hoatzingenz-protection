package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func ExecuteWPCLI(domain string, cliCmd string) (string, error) {
	docRoot := SiteRootDir(domain)
	if _, err := os.Stat(docRoot); os.IsNotExist(err) {
		localFallback := filepath.Join("./data/sites", domain)
		if _, err2 := os.Stat(localFallback); err2 == nil {
			docRoot = localFallback
		} else {
			return "", fmt.Errorf("site directory for domain %s not found", domain)
		}
	}

	cliCmd = strings.TrimSpace(cliCmd)
	if strings.HasPrefix(cliCmd, "wp ") {
		cliCmd = strings.TrimPrefix(cliCmd, "wp ")
	}

	if strings.Contains(cliCmd, ";") || strings.Contains(cliCmd, "&&") || strings.Contains(cliCmd, "||") || strings.Contains(cliCmd, "`") {
		return "", fmt.Errorf("invalid characters in command string")
	}

	wpPath, err := exec.LookPath("wp")
	if err != nil {
		wpPath = "/usr/local/bin/wp"
	}

	if _, err := os.Stat(wpPath); os.IsNotExist(err) {
		return fmt.Sprintf("[WP-CLI NOTICE] wp binary not installed on host server. Command 'wp %s' simulated for %s", cliCmd, domain), nil
	}

	args := []string{"--path=" + docRoot, "--allow-root"}
	args = append(args, strings.Fields(cliCmd)...)

	out, err := runCmd(60*time.Second, wpPath, args...)
	if err != nil {
		return RedactSecrets(out), err
	}
	return RedactSecrets(out), nil
}

func ExecuteArtisan(domain string, artisanCmd string) (string, error) {
	docRoot := SiteRootDir(domain)
	if _, err := os.Stat(docRoot); os.IsNotExist(err) {
		localFallback := filepath.Join("./data/sites", domain)
		if _, err2 := os.Stat(localFallback); err2 == nil {
			docRoot = localFallback
		} else {
			return "", fmt.Errorf("site directory for domain %s not found", domain)
		}
	}

	artisanCmd = strings.TrimSpace(artisanCmd)
	if strings.HasPrefix(artisanCmd, "php artisan ") {
		artisanCmd = strings.TrimPrefix(artisanCmd, "php artisan ")
	} else if strings.HasPrefix(artisanCmd, "artisan ") {
		artisanCmd = strings.TrimPrefix(artisanCmd, "artisan ")
	}

	if strings.Contains(artisanCmd, ";") || strings.Contains(artisanCmd, "&&") || strings.Contains(artisanCmd, "||") || strings.Contains(artisanCmd, "`") {
		return "", fmt.Errorf("invalid characters in command string")
	}

	artisanFile := filepath.Join(docRoot, "artisan")
	if _, err := os.Stat(artisanFile); os.IsNotExist(err) {
		return fmt.Sprintf("[ARTISAN NOTICE] Laravel artisan binary not found at %s. Command 'php artisan %s' simulated for %s", artisanFile, artisanCmd, domain), nil
	}

	phpPath, err := exec.LookPath("php")
	if err != nil {
		phpPath = "php"
	}

	args := []string{artisanFile}
	args = append(args, strings.Fields(artisanCmd)...)

	out, err := runCmd(60*time.Second, phpPath, args...)
	if err != nil {
		return RedactSecrets(out), err
	}
	return RedactSecrets(out), nil
}
