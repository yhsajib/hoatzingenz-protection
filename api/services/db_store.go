package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
	"strings"

	"hoatzingenz-protection/api/models"
	_ "modernc.org/sqlite"
)

type DBStore struct {
	db        *sql.DB
	mu        sync.RWMutex
	diagSites map[string]bool
}

func NewDBStore(dbPath string) (*DBStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Set connection pragma for concurrency and safety
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		log.Printf("[WARN] Failed to set WAL pragma: %v", err)
	}

	store := &DBStore{db: db, diagSites: make(map[string]bool)}
	if err := store.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize db tables: %w", err)
	}

	store.seedInitialData()

	return store, nil
}

func (s *DBStore) initTables() error {
	_, _ = s.db.Exec("ALTER TABLE websites ADD COLUMN deep_diagnostics_enabled INTEGER DEFAULT 0;")
	_, _ = s.db.Exec("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0;")
	_, _ = s.db.Exec("ALTER TABLE users ADD COLUMN two_factor_secret TEXT DEFAULT '';")
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin',
			two_factor_enabled INTEGER DEFAULT 0,
			two_factor_secret TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS websites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			team_id INTEGER DEFAULT 1,
			domain_name TEXT UNIQUE NOT NULL,
			document_root TEXT NOT NULL,
			php_version TEXT NOT NULL DEFAULT '8.3',
			site_type TEXT NOT NULL DEFAULT 'wordpress',
			app_port INTEGER DEFAULT 0,
			ssl_enabled INTEGER NOT NULL DEFAULT 1,
			ssl_provider TEXT DEFAULT 'letsencrypt',
			ssl_auto_renew INTEGER DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'active',
			tracking_id TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			source TEXT NOT NULL,
			server_id TEXT DEFAULT 'srv_prod_01',
			target_path TEXT NOT NULL,
			payload TEXT,
			is_quarantined INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS server_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id TEXT NOT NULL,
			cpu_percent REAL NOT NULL,
			ram_percent REAL NOT NULL,
			disk_percent REAL NOT NULL,
			load_1min REAL NOT NULL,
			load_5min REAL NOT NULL,
			load_15min REAL NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS mail_domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			team_id INTEGER DEFAULT 1,
			name TEXT UNIQUE NOT NULL,
			status TEXT DEFAULT 'verified',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS mailboxes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain_id INTEGER NOT NULL,
			local_part TEXT NOT NULL,
			address TEXT UNIQUE NOT NULL,
			quota_mb INTEGER DEFAULT 2048,
			active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS server_databases (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			team_id INTEGER DEFAULT 1,
			name TEXT UNIQUE NOT NULL,
			engine TEXT DEFAULT 'mysql',
			host TEXT DEFAULT '127.0.0.1',
			port INTEGER DEFAULT 3306,
			charset TEXT DEFAULT 'utf8mb4',
			"collate" TEXT DEFAULT 'utf8mb4_unicode_ci',
			username TEXT,
			password TEXT,
			connection_uri TEXT,
			size_mb REAL DEFAULT 0.0,
			status TEXT DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS ftp_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			website_id INTEGER,
			domain_name TEXT NOT NULL,
			username TEXT UNIQUE NOT NULL,
			path TEXT NOT NULL,
			status TEXT DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			key_hash TEXT UNIQUE NOT NULL,
			prefix TEXT NOT NULL,
			role TEXT DEFAULT 'agent',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
				`CREATE TABLE IF NOT EXISTS user_sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER DEFAULT 1,
			username TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin',
			ip_address TEXT NOT NULL,
			mac_address TEXT NOT NULL,
			user_agent TEXT NOT NULL,
			device_info TEXT NOT NULL,
			location TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_active DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS cron_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			website_id INTEGER DEFAULT 0,
			domain_name TEXT NOT NULL,
			schedule TEXT NOT NULL DEFAULT '0 * * * *',
			command TEXT NOT NULL,
			active INTEGER DEFAULT 1,
			last_run TEXT DEFAULT 'Never',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			log.Printf("[WARN] Error running table DDL query: %v", err)
		}
	}

	return nil
}

func HashAPIKey(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key + "_hoatzin_salt_2026"))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (s *DBStore) seedInitialData() {
	var userCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount == 0 {
		hash, _ := HashPassword("admin123")
		_, _ = s.db.Exec("INSERT INTO users (username, password_hash, role, two_factor_enabled, two_factor_secret) VALUES (?, ?, ?, 0, '')", "admin", hash, "admin")
		log.Printf("[INFO] Initialized default admin user (Username: admin)")
	}

	var keyCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&keyCount)
	if keyCount == 0 {
		defaultKey := "hz_agent_secret_key_2026"
		keyHash := HashAPIKey(defaultKey)
		_, _ = s.db.Exec("INSERT INTO api_keys (name, key_hash, prefix, role) VALUES (?, ?, ?, ?)", "Default Security Agent Key", keyHash, "hz_agent", "agent")
	}
}

// GetUsers returns all registered users
func (s *DBStore) GetUsers() []models.User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, username, role, two_factor_enabled, created_at FROM users ORDER BY id ASC")
	if err != nil {
		return []models.User{}
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var u models.User
		var twoFA int
		var createdAtStr string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &twoFA, &createdAtStr); err == nil {
			u.TwoFactorEnabled = (twoFA == 1)
			u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			users = append(users, u)
		}
	}
	return users
}

// User & Auth
func (s *DBStore) GetUserByUsername(username string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var u models.User
	var createdAtStr string
	var twoFactorEnabledInt int
	err := s.db.QueryRow("SELECT id, username, password_hash, role, COALESCE(two_factor_enabled, 0), COALESCE(two_factor_secret, ''), created_at FROM users WHERE username = ?", username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &twoFactorEnabledInt, &u.TwoFactorSecret, &createdAtStr)
	if err != nil {
		return nil, err
	}
	u.TwoFactorEnabled = twoFactorEnabledInt == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	return &u, nil
}

func (s *DBStore) UpdateUserPassword(username, newHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", newHash, username)
	return err
}

func (s *DBStore) UpdateUser2FA(username string, enabled bool, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := s.db.Exec("UPDATE users SET two_factor_enabled = ?, two_factor_secret = ? WHERE username = ?", enabledInt, secret, username)
	return err
}

func (s *DBStore) VerifyAPIKey(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyHash := HashAPIKey(key)
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM api_keys WHERE key_hash = ?", keyHash).Scan(&count)
	return count > 0
}

// Websites CRUD
func (s *DBStore) GetWebsites() []models.Website {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, team_id, domain_name, document_root, php_version, site_type, ssl_enabled, ssl_provider, status, tracking_id, created_at FROM websites ORDER BY id DESC")
	if err != nil {
		return []models.Website{}
	}
	defer rows.Close()

	list := make([]models.Website, 0)
	for rows.Next() {
		var w models.Website
		var sslInt int
		var createdAtStr string
		if err := rows.Scan(&w.ID, &w.TeamID, &w.DomainName, &w.DocumentRoot, &w.PHPVersion, &w.SiteType, &sslInt, &w.SSLProvider, &w.Status, &w.TrackingID, &createdAtStr); err == nil {
			w.SSLEnabled = sslInt == 1
			w.SSLAutoRenew = true
			w.PHPSettings = models.PHPSettings{
				MemoryLimit:       "256M",
				UploadMaxFilesize: "64M",
				MaxExecutionTime:  300,
				DisplayErrors:     false,
				OpcacheEnabled:    true,
			}
			w.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			if w.PreviewURL == "" {
				w.PreviewURL = "/sites/" + w.DomainName + "/"
			}
			if s.diagSites != nil {
				w.DeepDiagnosticsEnabled = s.diagSites[strings.ToLower(w.DomainName)]
			}
			list = append(list, w)
		}
	}
	return list
}

func (s *DBStore) AddWebsite(w models.Website) models.Website {
	s.mu.Lock()
	defer s.mu.Unlock()

	w.CreatedAt = time.Now()
	if w.TrackingID == "" {
		w.TrackingID = fmt.Sprintf("trk_%d", time.Now().UnixNano())
	}
	sslInt := 0
	if w.SSLEnabled {
		sslInt = 1
	}

	res, err := s.db.Exec("INSERT INTO websites (team_id, domain_name, document_root, php_version, site_type, ssl_enabled, ssl_provider, status, tracking_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		w.TeamID, w.DomainName, w.DocumentRoot, w.PHPVersion, w.SiteType, sslInt, w.SSLProvider, w.Status, w.TrackingID)
	if err == nil {
		w.ID, _ = res.LastInsertId()
	}
	return w
}


func (s *DBStore) SetWebsiteDeepDiagnostics(domain string, enabled bool) bool {
	s.mu.Lock()
	if s.diagSites == nil {
		s.diagSites = make(map[string]bool)
	}
	s.diagSites[strings.ToLower(domain)] = enabled
	s.mu.Unlock()

	intVal := 0
	if enabled {
		intVal = 1
	}
	_, _ = s.db.Exec("UPDATE websites SET deep_diagnostics_enabled = ? WHERE LOWER(domain_name) = LOWER(?)", intVal, domain)
	return true
}

func (s *DBStore) GetWebsiteDeepDiagnostics(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.diagSites == nil {
		return false
	}
	return s.diagSites[strings.ToLower(domain)]
}

func (s *DBStore) DeleteWebsite(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("DELETE FROM websites WHERE id = ?", id)
	if err != nil {
		return false
	}
	rowsAffected, _ := res.RowsAffected()
	return rowsAffected > 0
}

func (s *DBStore) GetWebsiteByID(id int64) (*models.Website, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var w models.Website
	var sslInt int
	var createdAtStr string
	err := s.db.QueryRow("SELECT id, team_id, domain_name, document_root, php_version, site_type, ssl_enabled, ssl_provider, status, tracking_id, created_at FROM websites WHERE id = ?", id).
		Scan(&w.ID, &w.TeamID, &w.DomainName, &w.DocumentRoot, &w.PHPVersion, &w.SiteType, &sslInt, &w.SSLProvider, &w.Status, &w.TrackingID, &createdAtStr)
	if err != nil {
		return nil, err
	}
	w.SSLEnabled = sslInt == 1
	w.SSLAutoRenew = true
	w.PHPSettings = models.PHPSettings{MemoryLimit: "256M", UploadMaxFilesize: "64M", MaxExecutionTime: 300, DisplayErrors: false, OpcacheEnabled: true}
	w.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	return &w, nil
}

func (s *DBStore) GetWebsiteByDomain(domain string) (*models.Website, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var w models.Website
	var sslInt int
	var createdAtStr string
	err := s.db.QueryRow("SELECT id, team_id, domain_name, document_root, php_version, site_type, ssl_enabled, ssl_provider, status, tracking_id, created_at FROM websites WHERE LOWER(domain_name) = LOWER(?)", domain).
		Scan(&w.ID, &w.TeamID, &w.DomainName, &w.DocumentRoot, &w.PHPVersion, &w.SiteType, &sslInt, &w.SSLProvider, &w.Status, &w.TrackingID, &createdAtStr)
	if err != nil {
		return nil, err
	}
	w.SSLEnabled = sslInt == 1
	w.SSLAutoRenew = true
	w.PHPSettings = models.PHPSettings{MemoryLimit: "256M", UploadMaxFilesize: "64M", MaxExecutionTime: 300, DisplayErrors: false, OpcacheEnabled: true}
	w.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	return &w, nil
}

func (s *DBStore) UpdateWebsiteStatus(domain string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE websites SET status = ? WHERE LOWER(domain_name) = LOWER(?)", status, domain)
	return err
}

// Security Events
func (s *DBStore) RecordSecurityEvent(e models.SecurityEvent) models.SecurityEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.CreatedAt = time.Now()
	e.Payload = RedactSecrets(e.Payload)

	quarantinedInt := 0
	if e.IsQuarantined {
		quarantinedInt = 1
	}

	res, err := s.db.Exec("INSERT INTO security_events (event_type, severity, source, server_id, target_path, payload, is_quarantined) VALUES (?, ?, ?, ?, ?, ?, ?)",
		e.EventType, e.Severity, e.Source, e.ServerID, e.TargetPath, e.Payload, quarantinedInt)
	if err == nil {
		e.ID, _ = res.LastInsertId()
	}
	return e
}

func (s *DBStore) GetSecurityEvents() []models.SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, event_type, severity, source, server_id, target_path, payload, is_quarantined, created_at FROM security_events ORDER BY id DESC LIMIT 100")
	if err != nil {
		return []models.SecurityEvent{}
	}
	defer rows.Close()

	list := make([]models.SecurityEvent, 0)
	for rows.Next() {
		var e models.SecurityEvent
		var qInt int
		var createdAtStr string
		if err := rows.Scan(&e.ID, &e.EventType, &e.Severity, &e.Source, &e.ServerID, &e.TargetPath, &e.Payload, &qInt, &createdAtStr); err == nil {
			e.IsQuarantined = qInt == 1
			e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			list = append(list, e)
		}
	}
	return list
}

// Metrics
func (s *DBStore) RecordMetric(m models.ServerMetric) models.ServerMetric {
	s.mu.Lock()
	defer s.mu.Unlock()

	m.CreatedAt = time.Now()
	res, err := s.db.Exec("INSERT INTO server_metrics (server_id, cpu_percent, ram_percent, disk_percent, load_1min, load_5min, load_15min) VALUES (?, ?, ?, ?, ?, ?, ?)",
		m.ServerID, m.CPUPercent, m.RAMPercent, m.DiskPercent, m.Load1Min, m.Load5Min, m.Load15Min)
	if err == nil {
		m.ID, _ = res.LastInsertId()
	}
	return m
}

func (s *DBStore) GetLatestMetric() *models.ServerMetric {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var m models.ServerMetric
	var createdAtStr string
	err := s.db.QueryRow("SELECT id, server_id, cpu_percent, ram_percent, disk_percent, load_1min, load_5min, load_15min, created_at FROM server_metrics ORDER BY id DESC LIMIT 1").
		Scan(&m.ID, &m.ServerID, &m.CPUPercent, &m.RAMPercent, &m.DiskPercent, &m.Load1Min, &m.Load5Min, &m.Load15Min, &createdAtStr)
	if err != nil {
		return nil
	}
	m.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	return &m
}

func (s *DBStore) GetMetricsHistory() []models.ServerMetric {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, server_id, cpu_percent, ram_percent, disk_percent, load_1min, load_5min, load_15min, created_at FROM server_metrics ORDER BY id DESC LIMIT 50")
	if err != nil {
		return []models.ServerMetric{}
	}
	defer rows.Close()

	list := make([]models.ServerMetric, 0)
	for rows.Next() {
		var m models.ServerMetric
		var createdAtStr string
		if err := rows.Scan(&m.ID, &m.ServerID, &m.CPUPercent, &m.RAMPercent, &m.DiskPercent, &m.Load1Min, &m.Load5Min, &m.Load15Min, &createdAtStr); err == nil {
			m.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			list = append(list, m)
		}
	}
	return list
}

// Mail & Databases CRUD
func (s *DBStore) GetDatabases() []models.ServerDatabase {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, team_id, name, engine, host, port, charset, \"collate\", username, password, connection_uri, size_mb, status FROM server_databases")
	if err != nil {
		// Fallback query if older schema
		rowsOld, errOld := s.db.Query("SELECT id, team_id, name, charset, \"collate\", driver, size_mb FROM server_databases")
		if errOld != nil {
			return []models.ServerDatabase{}
		}
		defer rowsOld.Close()
		list := make([]models.ServerDatabase, 0)
		for rowsOld.Next() {
			var db models.ServerDatabase
			if err := rowsOld.Scan(&db.ID, &db.TeamID, &db.Name, &db.Charset, &db.Collate, &db.Engine, &db.SizeMB); err == nil {
				if db.Engine == "" {
					db.Engine = "mysql"
				}
				db.Host = "127.0.0.1"
				db.Port = 3306
				db.ConnectionURI = fmt.Sprintf("mysql://root@127.0.0.1:3306/%s", db.Name)
				db.Status = "active"
				list = append(list, db)
			}
		}
		return list
	}
	defer rows.Close()

	list := make([]models.ServerDatabase, 0)
	for rows.Next() {
		var db models.ServerDatabase
		if err := rows.Scan(&db.ID, &db.TeamID, &db.Name, &db.Engine, &db.Host, &db.Port, &db.Charset, &db.Collate, &db.Username, &db.Password, &db.ConnectionURI, &db.SizeMB, &db.Status); err == nil {
			list = append(list, db)
		}
	}
	return list
}

func (s *DBStore) AddDatabase(db models.ServerDatabase) models.ServerDatabase {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	res, err := s.db.Exec("INSERT INTO server_databases (team_id, name, engine, host, port, charset, \"collate\", username, password, connection_uri, size_mb, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		db.TeamID, db.Name, db.Engine, db.Host, db.Port, db.Charset, db.Collate, db.Username, db.Password, db.ConnectionURI, db.SizeMB, db.Status)
	if err == nil {
		db.ID, _ = res.LastInsertId()
	}
	return db
}

func (s *DBStore) DeleteDatabase(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("DELETE FROM server_databases WHERE id = ?", id)
	if err != nil {
		return false
	}
	rowsAffected, _ := res.RowsAffected()
	return rowsAffected > 0
}

func (s *DBStore) GetDatabaseByID(id int64) (*models.ServerDatabase, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var db models.ServerDatabase
	err := s.db.QueryRow("SELECT id, team_id, name, engine, host, port, charset, \"collate\", username, password, connection_uri, size_mb, status FROM server_databases WHERE id = ?", id).
		Scan(&db.ID, &db.TeamID, &db.Name, &db.Engine, &db.Host, &db.Port, &db.Charset, &db.Collate, &db.Username, &db.Password, &db.ConnectionURI, &db.SizeMB, &db.Status)
	if err != nil {
		return nil, err
	}
	return &db, nil
}

func (s *DBStore) GetDatabaseByName(name string) (*models.ServerDatabase, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var db models.ServerDatabase
	err := s.db.QueryRow("SELECT id, team_id, name, engine, host, port, charset, \"collate\", username, password, connection_uri, size_mb, status FROM server_databases WHERE LOWER(name) = LOWER(?)", name).
		Scan(&db.ID, &db.TeamID, &db.Name, &db.Engine, &db.Host, &db.Port, &db.Charset, &db.Collate, &db.Username, &db.Password, &db.ConnectionURI, &db.SizeMB, &db.Status)
	if err != nil {
		return nil, err
	}
	return &db, nil
}

func (s *DBStore) UpdateDatabasePassword(name, newPassword, newURI string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE server_databases SET password = ?, connection_uri = ? WHERE LOWER(name) = LOWER(?)", newPassword, newURI, name)
	return err
}

func (s *DBStore) UpdateDatabaseSize(name string, sizeMB float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.db.Exec("UPDATE server_databases SET size_mb = ? WHERE name = ?", sizeMB, name)
}

// Cron Jobs
func (s *DBStore) GetCronJobs(domain string) []models.CronJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rows *sql.Rows
	var err error
	if domain != "" {
		rows, err = s.db.Query("SELECT id, website_id, domain_name, schedule, command, active, last_run, created_at FROM cron_jobs WHERE domain_name = ? ORDER BY id DESC", domain)
	} else {
		rows, err = s.db.Query("SELECT id, website_id, domain_name, schedule, command, active, last_run, created_at FROM cron_jobs ORDER BY id DESC")
	}
	if err != nil {
		return []models.CronJob{}
	}
	defer rows.Close()

	list := make([]models.CronJob, 0)
	for rows.Next() {
		var c models.CronJob
		var activeInt int
		var createdAtStr string
		if err := rows.Scan(&c.ID, &c.WebsiteID, &c.DomainName, &c.Schedule, &c.Command, &activeInt, &c.LastRun, &createdAtStr); err == nil {
			c.Active = activeInt == 1
			c.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			list = append(list, c)
		}
	}
	return list
}

func (s *DBStore) AddCronJob(c models.CronJob) models.CronJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	c.CreatedAt = time.Now()
	activeInt := 0
	if c.Active {
		activeInt = 1
	}
	res, err := s.db.Exec("INSERT INTO cron_jobs (website_id, domain_name, schedule, command, active, last_run) VALUES (?, ?, ?, ?, ?, ?)",
		c.WebsiteID, c.DomainName, c.Schedule, c.Command, activeInt, c.LastRun)
	if err == nil {
		c.ID, _ = res.LastInsertId()
	}
	return c
}

func (s *DBStore) DeleteCronJob(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("DELETE FROM cron_jobs WHERE id = ?", id)
	if err != nil {
		return false
	}
	rowsAffected, _ := res.RowsAffected()
	return rowsAffected > 0
}

func (s *DBStore) GetMailDomains() []models.MailDomain {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, team_id, name, status, created_at FROM mail_domains")
	if err != nil {
		return []models.MailDomain{}
	}
	defer rows.Close()

	list := make([]models.MailDomain, 0)
	for rows.Next() {
		var m models.MailDomain
		var createdAtStr string
		if err := rows.Scan(&m.ID, &m.TeamID, &m.Name, &m.Status, &createdAtStr); err == nil {
			m.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			list = append(list, m)
		}
	}
	return list
}

func (s *DBStore) GetMailboxes() []models.Mailbox {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, domain_id, local_part, address, quota_mb, active, created_at FROM mailboxes")
	if err != nil {
		return []models.Mailbox{}
	}
	defer rows.Close()

	list := make([]models.Mailbox, 0)
	for rows.Next() {
		var mb models.Mailbox
		var activeInt int
		var createdAtStr string
		if err := rows.Scan(&mb.ID, &mb.DomainID, &mb.LocalPart, &mb.Address, &mb.QuotaMB, &activeInt, &createdAtStr); err == nil {
			mb.Active = activeInt == 1
			mb.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
			list = append(list, mb)
		}
	}
	return list
}

func (s *DBStore) AddMailDomain(name string) (*models.MailDomain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("INSERT INTO mail_domains (team_id, name, status, created_at) VALUES (1, ?, 'verified', DATETIME('now'))", name)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.MailDomain{
		ID:        id,
		TeamID:    1,
		Name:      name,
		Status:    "verified",
		CreatedAt: time.Now(),
	}, nil
}

func (s *DBStore) DeleteMailDomain(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, _ = s.db.Exec("DELETE FROM mailboxes WHERE domain_id = ?", id)
	_, err := s.db.Exec("DELETE FROM mail_domains WHERE id = ?", id)
	return err
}

func (s *DBStore) AddMailbox(domainID int64, localPart, address string, quotaMB int64) (*models.Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("INSERT INTO mailboxes (domain_id, local_part, address, quota_mb, active, created_at) VALUES (?, ?, ?, ?, 1, DATETIME('now'))", domainID, localPart, address, quotaMB)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.Mailbox{
		ID:        id,
		DomainID:  domainID,
		LocalPart: localPart,
		Address:   address,
		QuotaMB:   quotaMB,
		Active:    true,
		CreatedAt: time.Now(),
	}, nil
}

func (s *DBStore) DeleteMailbox(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM mailboxes WHERE id = ?", id)
	return err
}

func (s *DBStore) Close() error {
	return s.db.Close()
}


// ---------------------------------------------------------------------------
// User Sessions Management (Superadmin & Hardware Tracking)
// ---------------------------------------------------------------------------

// CreateSession inserts or updates an active user session
func (s *DBStore) CreateSession(sess models.UserSession) error {
	query := `INSERT OR REPLACE INTO user_sessions (
		id, user_id, username, role, ip_address, mac_address, user_agent, device_info, location, token_hash, is_active, created_at, last_active
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query,
		sess.ID, sess.UserID, sess.Username, sess.Role, sess.IPAddress, sess.MACAddress,
		sess.UserAgent, sess.DeviceInfo, sess.Location, sess.TokenHash, 1, sess.CreatedAt, sess.CreatedAt,
	)
	return err
}

// GetActiveSessions returns all active sessions (is_active = 1) ordered by last_active DESC
func (s *DBStore) GetActiveSessions() []models.UserSession {
	query := `SELECT id, user_id, username, role, ip_address, mac_address, user_agent, device_info, location, token_hash, is_active, created_at, last_active
	          FROM user_sessions WHERE is_active = 1 ORDER BY last_active DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return []models.UserSession{}
	}
	defer rows.Close()

	sessions := make([]models.UserSession, 0)
	for rows.Next() {
		var sess models.UserSession
		var lastActiveTime time.Time
		var createdAtTime time.Time
		var isAct int
		if err := rows.Scan(
			&sess.ID, &sess.UserID, &sess.Username, &sess.Role, &sess.IPAddress, &sess.MACAddress,
			&sess.UserAgent, &sess.DeviceInfo, &sess.Location, &sess.TokenHash, &isAct,
			&createdAtTime, &lastActiveTime,
		); err == nil {
			sess.IsActive = (isAct == 1)
			sess.CreatedAt = createdAtTime
			sess.LastActive = FormatRelativeTime(lastActiveTime)
			sessions = append(sessions, sess)
		}
	}
	return sessions
}

// GetUserSessions returns all active sessions for a specific user
func (s *DBStore) GetUserSessions(username string) []models.UserSession {
	query := `SELECT id, user_id, username, role, ip_address, mac_address, user_agent, device_info, location, token_hash, is_active, created_at, last_active
	          FROM user_sessions WHERE username = ? AND is_active = 1 ORDER BY last_active DESC`
	rows, err := s.db.Query(query, username)
	if err != nil {
		return []models.UserSession{}
	}
	defer rows.Close()

	sessions := make([]models.UserSession, 0)
	for rows.Next() {
		var sess models.UserSession
		var lastActiveTime time.Time
		var createdAtTime time.Time
		var isAct int
		if err := rows.Scan(
			&sess.ID, &sess.UserID, &sess.Username, &sess.Role, &sess.IPAddress, &sess.MACAddress,
			&sess.UserAgent, &sess.DeviceInfo, &sess.Location, &sess.TokenHash, &isAct,
			&createdAtTime, &lastActiveTime,
		); err == nil {
			sess.IsActive = (isAct == 1)
			sess.CreatedAt = createdAtTime
			sess.LastActive = FormatRelativeTime(lastActiveTime)
			sessions = append(sessions, sess)
		}
	}
	return sessions
}

// TouchSession updates the last_active timestamp for a token hash
func (s *DBStore) TouchSession(tokenHash string) {
	if tokenHash != "" {
		_, _ = s.db.Exec(`UPDATE user_sessions SET last_active = CURRENT_TIMESTAMP WHERE token_hash = ? AND is_active = 1`, tokenHash)
	}
}

// RevokeSession terminates a session by ID
func (s *DBStore) RevokeSession(sessionID string) error {
	_, err := s.db.Exec(`UPDATE user_sessions SET is_active = 0 WHERE id = ?`, sessionID)
	return err
}

// RevokeAllUserSessionsExcept terminates all active sessions for a user except the specified one
func (s *DBStore) RevokeAllUserSessionsExcept(username string, exceptID string) error {
	_, err := s.db.Exec(`UPDATE user_sessions SET is_active = 0 WHERE username = ? AND id != ?`, username, exceptID)
	return err
}

// IsSessionRevoked checks if a token hash corresponds to a revoked/inactive session
func (s *DBStore) IsSessionRevoked(tokenHash string) bool {
	if tokenHash == "" {
		return false
	}
	var isActive int
	err := s.db.QueryRow(`SELECT is_active FROM user_sessions WHERE token_hash = ?`, tokenHash).Scan(&isActive)
	if err != nil {
		return false
	}
	return isActive == 0
}

// RevokeAllSessionsExceptToken terminates all active sessions except the specified token hash
func (s *DBStore) RevokeAllSessionsExceptToken(tokenHash string) error {
	_, err := s.db.Exec("UPDATE user_sessions SET is_active = 0 WHERE token_hash != ?", tokenHash)
	return err
}
