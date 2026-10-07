package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ExecuteTerminalCommand(domain string, cmdStr string) (string, string, error) {
	docRoot := SiteRootDir(domain)
	if _, err := os.Stat(docRoot); os.IsNotExist(err) {
		localFallback := filepath.Join("./data/sites", domain)
		if _, err2 := os.Stat(localFallback); err2 == nil {
			docRoot = localFallback
		} else {
			return "", "", fmt.Errorf("directory for domain %s not found", domain)
		}
	}

	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return "", docRoot, nil
	}

	dangerous := []string{"rm -rf /", "rm -rf /*", "mkfs", "dd if=", ":(){ :|:& };:", "shutdown", "reboot", "init 0"}
	for _, d := range dangerous {
		if strings.Contains(cmdStr, d) {
			return "Security Violation: Dangerous destructive system command blocked.", docRoot, fmt.Errorf("command blocked by security policy")
		}
	}

	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Dir = docRoot

	outBytes, err := cmd.CombinedOutput()
	output := RedactSecrets(string(outBytes))

	if err != nil && output == "" {
		output = err.Error()
	}

	return output, docRoot, nil
}
