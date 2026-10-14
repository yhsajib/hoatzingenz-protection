package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hoatzingenz/diagnostic-agent/config"
	"github.com/hoatzingenz/diagnostic-agent/spool"
	"github.com/hoatzingenz/diagnostic-agent/watcher"
)

type DiagnosticSiteTarget struct {
	DomainName   string `json:"domain_name"`
	DocumentRoot string `json:"document_root"`
	Enabled      bool   `json:"enabled"`
}

func getActiveDiagnosticTargets() []DiagnosticSiteTarget {
	candidateFiles := []string{
		"/var/lib/hoatzingenz/diagnostic_sites.json",
		"/etc/diagnostic-agent/enabled_sites.json",
	}
	for _, f := range candidateFiles {
		data, err := os.ReadFile(f)
		if err == nil {
			var targets []DiagnosticSiteTarget
			if err := json.Unmarshal(data, &targets); err == nil {
				var active []DiagnosticSiteTarget
				for _, t := range targets {
					if t.Enabled && t.DocumentRoot != "" {
						active = append(active, t)
					}
				}
				return active
			}
		}
	}
	return nil
}

func main() {
	configPath := flag.String("config", "/etc/diagnostic-agent/config.yaml", "Path to configuration file")
	flag.Parse()

	log.Println("==================================================================")
	log.Println(" Starting Hoatzingenz Diagnostic & Security Protection Agent")
	log.Println(" Mode: On-Demand Targeted Load-Balanced Deep Diagnostics")
	log.Println("==================================================================")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration: %v", err)
	}

	log.Printf("[INFO] Agent ID: %s | Environment: %s", cfg.ServerID, cfg.Environment)

	spooler, err := spool.NewSpoolManager(cfg.SpoolDirectory, 52428800)
	if err != nil {
		log.Printf("[WARN] Failed to initialize spool manager: %v", err)
	} else {
		log.Printf("[INFO] Spool manager initialized at %s", cfg.SpoolDirectory)
		_ = spooler
	}

	fim := watcher.NewFIMWatcher([]string{}, cfg.QuarantineDir, cfg.AutoQuarantine)
	procWatcher := watcher.NewProcessWatcher(cfg.WebUsers)

	log.Println("[INFO] FIM file watcher and Process watcher ready.")

	// Initial target evaluation
	activeTargets := getActiveDiagnosticTargets()
	if len(activeTargets) == 0 {
		log.Println("[STANDBY] Diagnostic Agent in standby mode (0 websites enabled). Monitoring suspended to balance panel & server load.")
	} else {
		log.Printf("[DEEP-DIAGNOSTIC] Targeted deep error analysis active for %d website(s):", len(activeTargets))
		for _, t := range activeTargets {
			log.Printf("  -> Active target: %s (%s)", t.DomainName, t.DocumentRoot)
			events, _ := fim.ScanDirectory(t.DocumentRoot)
			if len(events) > 0 {
				log.Printf("[ALERT] Found %d security/error events in %s", len(events), t.DomainName)
			}
		}
	}

	// Inspect real Linux /proc filesystem for active unauthorized processes spawned by web users
	for _, realAlert := range procWatcher.ScanLinuxProcFS() {
		log.Printf("[SECURITY ALERT] %s", realAlert.Message)
	}

	log.Println("[INFO] Agent entering dynamic load-balanced monitoring loop...")

	// Dynamic target polling loop (every 15s)
	ticker := time.NewTicker(15 * time.Second)
	lastTargetsCount := len(activeTargets)
	for range ticker.C {
		currentTargets := getActiveDiagnosticTargets()
		if len(currentTargets) != lastTargetsCount {
			lastTargetsCount = len(currentTargets)
			if len(currentTargets) == 0 {
				log.Println("[STANDBY] All deep diagnostic targets deactivated. Diagnostic Agent returned to standby (0% overhead).")
			} else {
				log.Printf("[DEEP-DIAGNOSTIC] Targets updated: Active deep analysis now running on %d website(s):", len(currentTargets))
				for _, t := range currentTargets {
					log.Printf("  -> Active target: %s (%s)", t.DomainName, t.DocumentRoot)
					events, _ := fim.ScanDirectory(t.DocumentRoot)
					if len(events) > 0 {
						log.Printf("[ALERT] Found %d security/error events in %s", len(events), t.DomainName)
					}
				}
			}
		}

		if len(currentTargets) > 0 {
			var domainNames []string
			for _, t := range currentTargets {
				domainNames = append(domainNames, t.DomainName)
			}
			log.Printf("[HEARTBEAT] Diagnostic Agent active (Targeted deep analysis on: %s) | Server: %s", strings.Join(domainNames, ", "), cfg.ServerID)
		} else {
			log.Printf("[HEARTBEAT] Diagnostic Agent in standby mode (0 active targets, 0%% load overhead) | Server: %s", cfg.ServerID)
		}
	}
}
