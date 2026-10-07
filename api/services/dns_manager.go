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

type DNSManager struct {
	mu      sync.Mutex
	records map[string][]*models.DNSRecord
	cfCfg   models.CloudflareConfig
}

var globalDNS *DNSManager
var dnsOnce sync.Once

func GetDNSManager() *DNSManager {
	dnsOnce.Do(func() {
		globalDNS = &DNSManager{
			records: make(map[string][]*models.DNSRecord),
		}
	})
	return globalDNS
}

func (d *DNSManager) AddRecord(rec models.DNSRecord) (*models.DNSRecord, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rec.ID = fmt.Sprintf("dns_%d", time.Now().UnixNano())
	if rec.TTL <= 0 {
		rec.TTL = 3600
	}

	d.records[rec.Domain] = append(d.records[rec.Domain], &rec)
	return &rec, nil
}

func (d *DNSManager) GetRecords(domain string) []*models.DNSRecord {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.records[domain]
}

func (d *DNSManager) DeleteRecord(domain string, id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	list := d.records[domain]
	var updated []*models.DNSRecord
	found := false
	for _, r := range list {
		if r.ID == id {
			found = true
			continue
		}
		updated = append(updated, r)
	}
	d.records[domain] = updated
	return found
}

func (d *DNSManager) SyncCloudflare(domain string, cfg models.CloudflareConfig) error {
	d.mu.Lock()
	d.cfCfg = cfg
	recs := d.records[domain]
	d.mu.Unlock()

	if cfg.APIToken == "" || cfg.ZoneID == "" {
		return fmt.Errorf("Cloudflare API token and Zone ID are required")
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", cfg.ZoneID)

	for _, r := range recs {
		body, _ := json.Marshal(map[string]interface{}{
			"type":    r.Type,
			"name":    r.Name,
			"content": r.Value,
			"ttl":     r.TTL,
			"proxied": r.Proxied,
		})

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}

	return nil
}
