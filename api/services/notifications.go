package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"hoatzingenz-protection/api/models"
)

type NotificationService struct {
	mu     sync.Mutex
	config models.NotificationConfig
}

var globalNotifier *NotificationService
var notifierOnce sync.Once

func GetNotificationService() *NotificationService {
	notifierOnce.Do(func() {
		globalNotifier = &NotificationService{
			config: models.NotificationConfig{
				AlertOnFail2Ban: true,
				AlertOnAutoHeal: true,
				AlertOnBackup:   true,
			},
		}
	})
	return globalNotifier
}

func (n *NotificationService) UpdateConfig(cfg models.NotificationConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config = cfg
}

func (n *NotificationService) GetConfig() models.NotificationConfig {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.config
}

func (n *NotificationService) SendAlert(subject string, message string) {
	n.mu.Lock()
	cfg := n.config
	n.mu.Unlock()

	fullMessage := fmt.Sprintf("[%s] %s\n%s", time.Now().Format("2006-01-02 15:04:05"), subject, message)

	// Telegram Bot Alert
	if cfg.TelegramEnabled && cfg.TelegramToken != "" && cfg.TelegramChatID != "" {
		go func() {
			url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.TelegramToken)
			body, _ := json.Marshal(map[string]string{
				"chat_id": cfg.TelegramChatID,
				"text":    fullMessage,
			})
			http.Post(url, "application/json", bytes.NewBuffer(body))
		}()
	}

	// Slack Webhook Alert
	if cfg.SlackEnabled && cfg.SlackWebhookURL != "" {
		go func() {
			body, _ := json.Marshal(map[string]string{
				"text": fullMessage,
			})
			http.Post(cfg.SlackWebhookURL, "application/json", bytes.NewBuffer(body))
		}()
	}
}
