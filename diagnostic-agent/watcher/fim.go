package watcher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Event struct {
	EventType   string    `json:"event_type"`
	Trigger     string    `json:"trigger"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	FilePath    string    `json:"file_path"`
	FileHash    string    `json:"file_hash"`
	Message     string    `json:"message"`
	Quarantined bool      `json:"quarantined"`
}

type FIMWatcher struct {
	watchPaths     []string
	quarantineDir  string
	autoQuarantine bool
	execExts       map[string]bool
}

func NewFIMWatcher(watchPaths []string, quarantineDir string, autoQuarantine bool) *FIMWatcher {
	exts := map[string]bool{
		".php":   true,
		".phtml": true,
		".php5":  true,
		".sh":    true,
		".so":    true,
		".exe":   true,
	}
	return &FIMWatcher{
		watchPaths:     watchPaths,
		quarantineDir:  quarantineDir,
		autoQuarantine: autoQuarantine,
		execExts:       exts,
	}
}

// StartInotifyWatcher initializes real-time kernel file event monitoring
func (f *FIMWatcher) StartInotifyWatcher(eventCallback func(Event)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to initialize fsnotify watcher: %w", err)
	}

	for _, watchPath := range f.watchPaths {
		_ = filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil && info.IsDir() {
				_ = watcher.Add(path)
			}
			return nil
		})
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case fsEvent, ok := <-watcher.Events:
				if !ok {
					return
				}

				if fsEvent.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					ext := strings.ToLower(filepath.Ext(fsEvent.Name))
					if f.execExts[ext] {
						hashStr, _ := computeSHA256(fsEvent.Name)
						evt := Event{
							EventType:   "SECURITY_ALERT",
							Trigger:     "WEBSHELL_DETECTED",
							Severity:    "CRITICAL",
							Timestamp:   time.Now(),
							FilePath:    fsEvent.Name,
							FileHash:    hashStr,
							Message:     fmt.Sprintf("Real-time inotify alert: Executable file drop detected at %s", fsEvent.Name),
							Quarantined: false,
						}

						if f.autoQuarantine && f.quarantineDir != "" {
							quarantined, err := f.QuarantineFile(fsEvent.Name)
							if err == nil && quarantined {
								evt.Quarantined = true
							}
						}

						if eventCallback != nil {
							eventCallback(evt)
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("[WARN] FIM fsnotify error: %v", err)
			}
		}
	}()

	log.Printf("[INFO] Real-time Linux kernel inotify watching active for %d paths", len(f.watchPaths))
	return nil
}

func (f *FIMWatcher) ScanDirectory(rootPath string) ([]Event, error) {
	var events []Event

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if f.execExts[ext] {
			hashStr, _ := computeSHA256(path)
			event := Event{
				EventType:   "SECURITY_ALERT",
				Trigger:     "WEBSHELL_DETECTED",
				Severity:    "CRITICAL",
				Timestamp:   time.Now(),
				FilePath:    path,
				FileHash:    hashStr,
				Message:     fmt.Sprintf("Executable file drop detected: %s", path),
				Quarantined: false,
			}

			if f.autoQuarantine && f.quarantineDir != "" {
				quarantined, err := f.QuarantineFile(path)
				if err == nil && quarantined {
					event.Quarantined = true
				}
			}

			events = append(events, event)
		}
		return nil
	})

	return events, err
}

func (f *FIMWatcher) QuarantineFile(filePath string) (bool, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, nil
	}

	_ = os.MkdirAll(f.quarantineDir, 0755)

	destName := fmt.Sprintf("%d_%s.quarantine", time.Now().Unix(), filepath.Base(filePath))
	destPath := filepath.Join(f.quarantineDir, destName)

	_ = os.Chmod(filePath, 0000)
	err := os.Rename(filePath, destPath)
	if err != nil {
		return false, err
	}

	log.Printf("[QUARANTINE] Successfully quarantined malicious drop: %s -> %s", filePath, destPath)
	return true, nil
}

func computeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
