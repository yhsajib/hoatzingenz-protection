package services

import (
	"fmt"
	"sync"
	"time"

	"hoatzingenz-protection/api/models"
)

type MemoryStore struct {
	mu               sync.RWMutex
	websites         []models.Website
	mailDomains      []models.MailDomain
	mailboxes        []models.Mailbox
	databases        []models.ServerDatabase
	ftpAccounts      []models.FTPAccount
	cronJobs         []models.CronJob
	securityEvents   []models.SecurityEvent
	errorDiagnostics []models.ErrorDiagnostic
	serverMetrics    []models.ServerMetric
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		websites:         make([]models.Website, 0),
		mailDomains:      make([]models.MailDomain, 0),
		mailboxes:        make([]models.Mailbox, 0),
		databases:        make([]models.ServerDatabase, 0),
		ftpAccounts:      make([]models.FTPAccount, 0),
		cronJobs:         make([]models.CronJob, 0),
		securityEvents:   make([]models.SecurityEvent, 0),
		errorDiagnostics: make([]models.ErrorDiagnostic, 0),
		serverMetrics:    make([]models.ServerMetric, 0),
	}

	// Seed error analysis diagnostics
	store.errorDiagnostics = append(store.errorDiagnostics,
		models.ErrorDiagnostic{
			ID:               101,
			IncidentID:       "inc_01H89X201A",
			RequestID:        "req_8819A91B",
			DomainName:       "hoatzinlabs.com",
			ErrorType:        "PHP_FATAL",
			Severity:         "CRITICAL",
			Category:         "Reliability",
			Message:          "Uncaught Error: Call to undefined function wp_remote_post() in /var/www/html/hoatzinlabs.com/wp-content/plugins/analytics/core.php:42",
			File:             "/var/www/html/hoatzinlabs.com/wp-content/plugins/analytics/core.php",
			Line:             42,
			StackTrace:       "#0 /var/www/html/hoatzinlabs.com/wp-settings.php(450): include_once()\n#1 /var/www/html/hoatzinlabs.com/wp-config.php(90): require_once()\n#2 /var/www/html/hoatzinlabs.com/index.php(17): require()",
			ConfidenceScore:  0.98,
			AIRootCause:      "Plugin 'analytics' invoked `wp_remote_post()` before WordPress HTTP API was loaded during early initialization hook.",
			RemediationSteps: []string{"Wrap call in `plugins_loaded` hook", "Check if function exists before execution", "Deactivate plugin 'analytics' v1.2"},
			CreatedAt:        time.Now().Add(-15 * time.Minute),
		},
		models.ErrorDiagnostic{
			ID:               102,
			IncidentID:       "inc_01H89X202B",
			RequestID:        "req_9921C32D",
			DomainName:       "cloud-wordpress.org",
			ErrorType:        "MEMORY_EXHAUSTED",
			Severity:         "ERROR",
			Category:         "Performance",
			Message:          "Allowed memory size of 268435456 bytes exhausted (tried to allocate 134217728 bytes) in /var/www/html/cloud-wordpress.org/wp-includes/plugin.php:204",
			File:             "/var/www/html/cloud-wordpress.org/wp-includes/plugin.php",
			Line:             204,
			StackTrace:       "#0 /var/www/html/cloud-wordpress.org/wp-content/plugins/seo/sitemap.php(112): do_action()\n#1 /var/www/html/cloud-wordpress.org/index.php(20): require()",
			ConfidenceScore:  0.94,
			AIRootCause:      "Sitemap generator plugin attempted to load 50,000 posts into a single PHP array without chunking or pagination.",
			RemediationSteps: []string{"Increase php.ini memory_limit to 512M", "Enable post chunking in SEO plugin config", "Clear sitemap cache"},
			CreatedAt:        time.Now().Add(-45 * time.Minute),
		},
		models.ErrorDiagnostic{
			ID:               103,
			IncidentID:       "inc_01H89X203C",
			RequestID:        "req_4412F55E",
			DomainName:       "api-service.dev",
			ErrorType:        "SLOW_QUERY",
			Severity:         "WARNING",
			Category:         "Performance",
			Message:          "Query execution latency breached threshold (3.42s > 0.50s): SELECT * FROM orders WHERE status = 'pending' ORDER BY created_at DESC",
			File:             "/var/www/html/api-service.dev/app/Repositories/OrderRepository.php",
			Line:             88,
			StackTrace:       "#0 /var/www/html/api-service.dev/app/Http/Controllers/OrderController.php(34): OrderRepository->getPending()",
			ConfidenceScore:  0.96,
			AIRootCause:      "Missing composite database index on `orders(status, created_at)` causing a full table scan over 1.2M rows.",
			RemediationSteps: []string{"Add index: CREATE INDEX idx_orders_status_created ON orders(status, created_at DESC);", "Optimize query SELECT fields"},
			CreatedAt:        time.Now().Add(-90 * time.Minute),
		},
	)

	// Seed sample initial website
	store.websites = append(store.websites, models.Website{
		ID:           1,
		TeamID:       1,
		DomainName:   "hoatzinlabs.com",
		DocumentRoot: "/var/www/html/hoatzinlabs.com",
		PHPVersion:   "8.3",
		SiteType:     "wordpress",
		SSLEnabled:   true,
		SSLProvider:  "letsencrypt",
		SSLAutoRenew: true,
		SSLIssuer:    "Let's Encrypt Authority X3",
		SSLExpiresAt: "2026-12-31 23:59:59",
		ForceHTTPS:   true,
		HSTSEnabled:  true,
		LinkedDBName: "wp_hoatzin_prod",
		Status:       "active",
		TrackingID:   "trk_demo_123456",
		PHPSettings: models.PHPSettings{
			MemoryLimit:       "256M",
			UploadMaxFilesize: "64M",
			MaxExecutionTime:  300,
			DisplayErrors:     false,
			OpcacheEnabled:    true,
		},
		Security: models.SiteSecurityConfig{
			WebsiteID:         1,
			DomainName:        "hoatzinlabs.com",
			WAFEnabled:        true,
			BlockSQLi:         true,
			BlockXSS:          true,
			ForceHTTPS:        true,
			HSTSEnabled:       true,
			HotlinkProtection: true,
			BasicAuthEnabled:  false,
		},
		CreatedAt: time.Now(),
	})

	// Seed initial cron jobs
	store.cronJobs = append(store.cronJobs,
		models.CronJob{
			ID:         1,
			WebsiteID:  1,
			DomainName: "hoatzinlabs.com",
			Schedule:   "*/15 * * * *",
			Command:    "php /var/www/html/hoatzinlabs.com/wp-cron.php",
			Active:     true,
			LastRun:    time.Now().Add(-10 * time.Minute).Format("15:04:05"),
			CreatedAt:  time.Now(),
		},
	)
	store.databases = append(store.databases,
		models.ServerDatabase{
			ID:            1,
			TeamID:        1,
			Name:          "wp_hoatzin_prod",
			Engine:        "mysql",
			Host:          "127.0.0.1",
			Port:          3306,
			Charset:       "utf8mb4",
			Collate:       "utf8mb4_unicode_ci",
			Username:      "wp_user_prod",
			ConnectionURI: "mysql://wp_user_prod:secret@127.0.0.1:3306/wp_hoatzin_prod",
			SizeMB:        48.5,
			Status:        "active",
			CreatedAt:     time.Now(),
		},
		models.ServerDatabase{
			ID:            2,
			TeamID:        1,
			Name:          "laravel_app_db",
			Engine:        "postgresql",
			Host:          "127.0.0.1",
			Port:          5432,
			Charset:       "utf8",
			Collate:       "en_US.UTF-8",
			Username:      "pg_laravel_user",
			ConnectionURI: "postgresql://pg_laravel_user:secret@127.0.0.1:5432/laravel_app_db?sslmode=disable",
			SizeMB:        124.2,
			Status:        "active",
			CreatedAt:     time.Now(),
		},
		models.ServerDatabase{
			ID:            3,
			TeamID:        1,
			Name:          "analytics_store",
			Engine:        "mongodb",
			Host:          "127.0.0.1",
			Port:          27017,
			Charset:       "utf8",
			Collate:       "binary",
			Username:      "mongo_analytics",
			ConnectionURI: "mongodb://mongo_analytics:secret@127.0.0.1:27017/analytics_store",
			SizeMB:        310.8,
			Status:        "active",
			CreatedAt:     time.Now(),
		},
		models.ServerDatabase{
			ID:            4,
			TeamID:        1,
			Name:          "cache_session_db",
			Engine:        "redis",
			Host:          "127.0.0.1",
			Port:          6379,
			Charset:       "binary",
			Username:      "default",
			ConnectionURI: "redis://:secret_pass@127.0.0.1:6379/0",
			SizeMB:        18.4,
			Status:        "active",
			CreatedAt:     time.Now(),
		},
		models.ServerDatabase{
			ID:            5,
			TeamID:        1,
			Name:          "app_embedded.sqlite",
			Engine:        "sqlite",
			Host:          "local",
			Port:          0,
			Charset:       "utf8",
			Username:      "system",
			ConnectionURI: "file:///var/www/html/hoatzinlabs.com/data/app_embedded.sqlite",
			SizeMB:        5.2,
			Status:        "active",
			CreatedAt:     time.Now(),
		},
	)

	store.mailDomains = append(store.mailDomains, models.MailDomain{
		ID:        1,
		TeamID:    1,
		Name:      "hoatzinlabs.com",
		Status:    "verified",
		CreatedAt: time.Now(),
	})

	store.mailboxes = append(store.mailboxes, models.Mailbox{
		ID:        1,
		DomainID:  1,
		LocalPart: "supports",
		Address:   "supports@hoatzinlabs.com",
		QuotaMB:   2048,
		Active:    true,
		CreatedAt: time.Now(),
	})

	store.serverMetrics = append(store.serverMetrics, models.ServerMetric{
		ID:          1,
		ServerID:    "srv_prod_01",
		CPUPercent:  12.4,
		RAMPercent:  38.2,
		DiskPercent: 24.8,
		Load1Min:    0.45,
		Load5Min:    0.50,
		Load15Min:   0.48,
		CreatedAt:   time.Now(),
	})

	return store
}

// Websites CRUD
func (s *MemoryStore) GetWebsites() []models.Website {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.websites
}

func (s *MemoryStore) AddWebsite(w models.Website) models.Website {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.ID = int64(len(s.websites) + 1)
	w.CreatedAt = time.Now()
	w.TrackingID = fmt.Sprintf("trk_%d", time.Now().UnixNano())
	if w.PHPSettings.MemoryLimit == "" {
		w.PHPSettings = models.PHPSettings{
			MemoryLimit:       "256M",
			UploadMaxFilesize: "64M",
			MaxExecutionTime:  300,
			DisplayErrors:     false,
			OpcacheEnabled:    true,
		}
	}
	s.websites = append(s.websites, w)
	return w
}

func (s *MemoryStore) DeleteWebsite(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.websites {
		if w.ID == id {
			s.websites = append(s.websites[:i], s.websites[i+1:]...)
			return true
		}
	}
	return false
}

// Databases CRUD
func (s *MemoryStore) GetDatabases() []models.ServerDatabase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.databases
}

func (s *MemoryStore) AddDatabase(db models.ServerDatabase) models.ServerDatabase {
	s.mu.Lock()
	defer s.mu.Unlock()
	db.ID = int64(len(s.databases) + 1)
	db.CreatedAt = time.Now()
	if db.Engine == "" {
		db.Engine = "mysql"
	}
	if db.Host == "" {
		db.Host = "127.0.0.1"
	}
	if db.Port == 0 {
		switch db.Engine {
		case "postgresql":
			db.Port = 5432
		case "mongodb":
			db.Port = 27017
		case "redis":
			db.Port = 6379
		default:
			db.Port = 3306
		}
	}
	if db.ConnectionURI == "" {
		switch db.Engine {
		case "postgresql":
			db.ConnectionURI = fmt.Sprintf("postgresql://%s:%s@%s:%d/%s", db.Username, db.Password, db.Host, db.Port, db.Name)
		case "mongodb":
			db.ConnectionURI = fmt.Sprintf("mongodb://%s:%s@%s:%d/%s", db.Username, db.Password, db.Host, db.Port, db.Name)
		case "redis":
			db.ConnectionURI = fmt.Sprintf("redis://:%s@%s:%d/0", db.Password, db.Host, db.Port)
		case "sqlite":
			db.ConnectionURI = fmt.Sprintf("file:///var/www/html/db/%s.sqlite", db.Name)
		default:
			db.ConnectionURI = fmt.Sprintf("mysql://%s:%s@%s:%d/%s", db.Username, db.Password, db.Host, db.Port, db.Name)
		}
	}
	db.Status = "active"
	s.databases = append(s.databases, db)
	return db
}

func (s *MemoryStore) DeleteDatabase(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, db := range s.databases {
		if db.ID == id {
			s.databases = append(s.databases[:i], s.databases[i+1:]...)
			return true
		}
	}
	return false
}

// FTP Accounts
func (s *MemoryStore) GetFTPAccounts() []models.FTPAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ftpAccounts
}

func (s *MemoryStore) AddFTPAccount(acc models.FTPAccount) models.FTPAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc.ID = int64(len(s.ftpAccounts) + 1)
	acc.CreatedAt = time.Now()
	acc.Status = "active"
	s.ftpAccounts = append(s.ftpAccounts, acc)
	return acc
}

// Security Events & Metrics
func (s *MemoryStore) RecordSecurityEvent(e models.SecurityEvent) models.SecurityEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = int64(len(s.securityEvents) + 1)
	e.CreatedAt = time.Now()
	s.securityEvents = append([]models.SecurityEvent{e}, s.securityEvents...)
	return e
}

func (s *MemoryStore) GetSecurityEvents() []models.SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.securityEvents
}

func (s *MemoryStore) RecordMetric(m models.ServerMetric) models.ServerMetric {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.ID = int64(len(s.serverMetrics) + 1)
	m.CreatedAt = time.Now()
	s.serverMetrics = append(s.serverMetrics, m)
	if len(s.serverMetrics) > 100 {
		s.serverMetrics = s.serverMetrics[1:]
	}
	return m
}

func (s *MemoryStore) GetLatestMetric() *models.ServerMetric {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.serverMetrics) == 0 {
		return nil
	}
	return &s.serverMetrics[len(s.serverMetrics)-1]
}

func (s *MemoryStore) GetMetricsHistory() []models.ServerMetric {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverMetrics
}

func (s *MemoryStore) GetCronJobs(domain string) []models.CronJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if domain == "" {
		return s.cronJobs
	}
	var res []models.CronJob
	for font, c := range s.cronJobs {
		_ = font
		if c.DomainName == domain {
			res = append(res, c)
		}
	}
	return res
}

func (s *MemoryStore) AddCronJob(c models.CronJob) models.CronJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.ID = int64(len(s.cronJobs) + 1)
	c.Active = true
	c.CreatedAt = time.Now()
	c.LastRun = "Just now"
	s.cronJobs = append(s.cronJobs, c)
	return c
}

func (s *MemoryStore) DeleteCronJob(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.cronJobs {
		if c.ID == id {
			s.cronJobs = append(s.cronJobs[:i], s.cronJobs[i+1:]...)
			return true
		}
	}
	return false
}

func (s *MemoryStore) GetErrorDiagnostics() []models.ErrorDiagnostic {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.errorDiagnostics
}

func (s *MemoryStore) RecordErrorDiagnostic(e models.ErrorDiagnostic) models.ErrorDiagnostic {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = int64(len(s.errorDiagnostics) + 101)
	e.CreatedAt = time.Now()
	if e.IncidentID == "" {
		e.IncidentID = fmt.Sprintf("inc_%d", time.Now().UnixNano())
	}
	s.errorDiagnostics = append([]models.ErrorDiagnostic{e}, s.errorDiagnostics...)
	return e
}

func (s *MemoryStore) GetMailDomains() []models.MailDomain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mailDomains
}

func (s *MemoryStore) GetMailboxes() []models.Mailbox {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mailboxes
}

func (s *MemoryStore) AddMailDomain(name string) (*models.MailDomain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := int64(len(s.mailDomains) + 1)
	md := models.MailDomain{
		ID:        id,
		TeamID:    1,
		Name:      name,
		Status:    "verified",
		CreatedAt: time.Now(),
	}
	s.mailDomains = append(s.mailDomains, md)
	return &md, nil
}

func (s *MemoryStore) DeleteMailDomain(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var newDomains []models.MailDomain
	for _, d := range s.mailDomains {
		if d.ID != id {
			newDomains = append(newDomains, d)
		}
	}
	s.mailDomains = newDomains

	var newBoxes []models.Mailbox
	for _, b := range s.mailboxes {
		if b.DomainID != id {
			newBoxes = append(newBoxes, b)
		}
	}
	s.mailboxes = newBoxes
	return nil
}

func (s *MemoryStore) AddMailbox(domainID int64, localPart, address string, quotaMB int64) (*models.Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := int64(len(s.mailboxes) + 1)
	mb := models.Mailbox{
		ID:        id,
		DomainID:  domainID,
		LocalPart: localPart,
		Address:   address,
		QuotaMB:   quotaMB,
		Active:    true,
		CreatedAt: time.Now(),
	}
	s.mailboxes = append(s.mailboxes, mb)
	return &mb, nil
}

func (s *MemoryStore) DeleteMailbox(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var newBoxes []models.Mailbox
	for _, b := range s.mailboxes {
		if b.ID != id {
			newBoxes = append(newBoxes, b)
		}
	}
	s.mailboxes = newBoxes
	return nil
}




func (s *MemoryStore) DeleteFTPAccount(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.ftpAccounts {
		if f.ID == id {
			s.ftpAccounts = append(s.ftpAccounts[:i], s.ftpAccounts[i+1:]...)
			return true
		}
	}
	return false
}
