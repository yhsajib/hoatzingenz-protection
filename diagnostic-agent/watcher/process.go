package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ProcessEvent struct {
	EventType   string    `json:"event_type"`
	Trigger     string    `json:"trigger"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	PID         int       `json:"pid"`
	User        string    `json:"user"`
	CommandLine string    `json:"command_line"`
	Message     string    `json:"message"`
}

type ProcessWatcher struct {
	webUsers           map[string]bool
	suspiciousBinaries []string
}

func NewProcessWatcher(webUsers []string) *ProcessWatcher {
	userMap := make(map[string]bool)
	for _, u := range webUsers {
		userMap[u] = true
	}
	if len(userMap) == 0 {
		userMap["www-data"] = true
		userMap["nobody"] = true
		userMap["nginx"] = true
		userMap["apache"] = true
	}

	return &ProcessWatcher{
		webUsers:           userMap,
		suspiciousBinaries: []string{"sh", "bash", "curl", "wget", "nc", "netcat", "python", "perl", "gcc"},
	}
}

func (p *ProcessWatcher) InspectProcess(pid int, user string, cmdline string) *ProcessEvent {
	if !p.webUsers[user] && user != "www-data" && user != "nobody" {
		return nil
	}

	for _, bin := range p.suspiciousBinaries {
		if strings.Contains(cmdline, bin) {
			return &ProcessEvent{
				EventType:   "SECURITY_ALERT",
				Trigger:     "SUSPICIOUS_PROCESS_SPAWN",
				Severity:    "CRITICAL",
				Timestamp:   time.Now(),
				PID:         pid,
				User:        user,
				CommandLine: cmdline,
				Message:     fmt.Sprintf("Web user [%s] spawned suspicious process [PID %d: %s]", user, pid, cmdline),
			}
		}
	}

	return nil
}

// ScanLinuxProcFS inspects active Linux PIDs in /proc filesystem
func (p *ProcessWatcher) ScanLinuxProcFS() []*ProcessEvent {
	var alerts []*ProcessEvent

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return alerts
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		cmdBytes, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		cmdline := strings.ReplaceAll(string(cmdBytes), "\x00", " ")

		if cmdline != "" {
			if alert := p.InspectProcess(pid, "www-data", cmdline); alert != nil {
				alerts = append(alerts, alert)
			}
		}
	}

	return alerts
}
