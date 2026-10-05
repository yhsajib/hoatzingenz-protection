package models

import "time"

// PHPSettings holds php.ini customization per website
type PHPSettings struct {
	MemoryLimit       string `json:"memory_limit"`       // e.g. 256M
	UploadMaxFilesize string `json:"upload_max_filesize"` // e.g. 64M
	MaxExecutionTime  int    `json:"max_execution_time"`  // e.g. 300
	DisplayErrors     bool   `json:"display_errors"`
	OpcacheEnabled    bool   `json:"opcache_enabled"`
}

// SiteSecurityConfig represents WAF, HTTPS, and auth settings for a website
type SiteSecurityConfig struct {
	WebsiteID          int64    `json:"website_id"`
	DomainName         string   `json:"domain_name"`
	WAFEnabled         bool     `json:"waf_enabled"`
	BlockSQLi          bool     `json:"block_sqli"`
	BlockXSS           bool     `json:"block_xss"`
	ForceHTTPS         bool     `json:"force_https"`
	HSTSEnabled        bool     `json:"hsts_enabled"`
	HotlinkProtection bool     `json:"hotlink_protection"`
	BasicAuthEnabled   bool     `json:"basic_auth_enabled"`
	BasicAuthUser      string   `json:"basic_auth_user,omitempty"`
	AllowedIPs         []string `json:"allowed_ips"`
	BlockedIPs         []string `json:"blocked_ips"`
}

// CronJob represents a scheduled task for a website
type CronJob struct {
	ID         int64     `json:"id"`
	WebsiteID  int64     `json:"website_id"`
	DomainName string    `json:"domain_name"`
	Schedule   string    `json:"schedule"` // e.g. "0 * * * *" or "* * * * *"
	Command    string    `json:"command"`  // e.g. "php /var/www/html/domain.com/artisan schedule:run"
	Active     bool      `json:"active"`
	LastRun    string    `json:"last_run"`
	CreatedAt  time.Time `json:"created_at"`
}

// FileItem represents a file or directory in the web file manager
type FileItem struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	IsDir       bool      `json:"is_dir"`
	Size        int64     `json:"size"`
	Permissions string    `json:"permissions"`
	Extension   string    `json:"extension"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Website represents a domain virtual host managed by the panel
type Website struct {
	ID           int64              `json:"id"`
	TeamID       int64              `json:"team_id"`
	DomainName   string             `json:"domain_name"`
	DocumentRoot string             `json:"document_root"`
	PHPVersion   string             `json:"php_version"` // 7.4, 8.0, 8.1, 8.2, 8.3, 8.4
	SiteType     string             `json:"site_type"`   // wordpress, laravel, nodejs, python, static, reverse_proxy
	AppPort      int                `json:"app_port"`    // For nodejs, python, proxy apps (e.g. 3000, 8000)
	SSLEnabled   bool               `json:"ssl_enabled"`
	SSLProvider  string             `json:"ssl_provider"` // letsencrypt, custom
	SSLAutoRenew bool               `json:"ssl_auto_renew"`
	SSLExpiresAt string             `json:"ssl_expires_at,omitempty"`
	SSLIssuer    string             `json:"ssl_issuer,omitempty"`
	ForceHTTPS   bool               `json:"force_https"`
	HSTSEnabled  bool               `json:"hsts_enabled"`
	LinkedDBID   int64              `json:"linked_db_id,omitempty"`
	LinkedDBName string             `json:"linked_db_name,omitempty"`
	Status              string             `json:"status"` // active, suspended, provisioning
	TrackingID          string             `json:"tracking_id"`
	SiteTitle           string             `json:"site_title,omitempty"`
	AdminUser           string             `json:"admin_user,omitempty"`
	AdminPass           string             `json:"admin_pass,omitempty"`
	AdminEmail          string             `json:"admin_email,omitempty"`
	DBName              string             `json:"db_name,omitempty"`
	DBUser              string             `json:"db_user,omitempty"`
	DBPass              string             `json:"db_pass,omitempty"`
	DBHost              string             `json:"db_host,omitempty"`
	AppKey              string             `json:"app_key,omitempty"`
	NodeVersion         string             `json:"node_version,omitempty"`
	PythonVersion       string             `json:"python_version,omitempty"`
	EntryScript         string             `json:"entry_script,omitempty"`
	ProcessManager      string             `json:"process_manager,omitempty"`
	NginxConfig         string             `json:"nginx_config,omitempty"`
	EnvFileContent      string             `json:"env_file_content,omitempty"`
	SystemdContent      string             `json:"systemd_content,omitempty"`
	FPMPoolContent      string             `json:"fpm_pool_content,omitempty"`
	DeployScriptContent string             `json:"deploy_script_content,omitempty"`
	PHPSettings         PHPSettings        `json:"php_settings"`
	Security            SiteSecurityConfig `json:"security"`
	CreatedAt           time.Time          `json:"created_at"`
}

// MailDomain represents an email domain
type MailDomain struct {
	ID        int64     `json:"id"`
	TeamID    int64     `json:"team_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// Mailbox represents an email account
type Mailbox struct {
	ID        int64     `json:"id"`
	DomainID  int64     `json:"domain_id"`
	LocalPart string    `json:"local_part"`
	Address   string    `json:"address"` // user@domain.com
	QuotaMB   int64     `json:"quota_mb"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// ServerDatabase supports MySQL, MariaDB, PostgreSQL, MongoDB, Redis, and SQLite
type ServerDatabase struct {
	ID            int64     `json:"id"`
	TeamID        int64     `json:"team_id"`
	Name          string    `json:"name"`
	Engine        string    `json:"engine"` // mysql, mariadb, postgresql, mongodb, redis, sqlite
	Host          string    `json:"host"`   // 127.0.0.1 or remote IP
	Port          int       `json:"port"`   // 3306, 5432, 27017, 6379
	Charset       string    `json:"charset"`
	Collate       string    `json:"collate"`
	Username      string    `json:"username"`
	Password      string    `json:"password,omitempty"`
	ConnectionURI string    `json:"connection_uri"`
	SizeMB        float64   `json:"size_mb"`
	Status        string    `json:"status"` // active, maintenance
	CreatedAt     time.Time `json:"created_at"`
}

// DatabaseUser represents a database user for MySQL/PostgreSQL/MongoDB
type DatabaseUser struct {
	ID         int64     `json:"id"`
	DatabaseID int64     `json:"database_id"`
	Username   string    `json:"username"`
	Engine     string    `json:"engine"`
	Host       string    `json:"host"`
	Privileges string    `json:"privileges"` // ALL, READ_WRITE, READ_ONLY
	CreatedAt  time.Time `json:"created_at"`
}

// FTPAccount represents an FTP/SFTP account per website
type FTPAccount struct {
	ID         int64     `json:"id"`
	WebsiteID  int64     `json:"website_id"`
	DomainName string    `json:"domain_name"`
	Username   string    `json:"username"`
	Path       string    `json:"path"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// SystemService represents managed daemon services (Nginx, PHP-FPM, MySQL, Postgres, Redis, Mongo)
type SystemService struct {
	Name     string  `json:"name"`
	Engine   string  `json:"engine"`
	Status   string  `json:"status"` // running, stopped
	Uptime   string  `json:"uptime"`
	MemoryMB float64 `json:"memory_mb"`
}

// SecurityEvent represents real-time FIM / malware / process alerts
type SecurityEvent struct {
	ID            int64     `json:"id"`
	EventType     string    `json:"event_type"` // WEBSHELL_DETECTED, FIM_MODIFIED, SUSPICIOUS_PROCESS
	Severity      string    `json:"severity"`   // low, medium, high, critical
	Source        string    `json:"source"`     // go-agent, php-sdk, wp-plugin
	ServerID      string    `json:"server_id"`
	TargetPath    string    `json:"target_path"`
	Payload       string    `json:"payload"`
	IsQuarantined bool      `json:"is_quarantined"`
	CreatedAt     time.Time `json:"created_at"`
}

// ServerMetric represents periodic CPU, RAM, Disk telemetry
type ServerMetric struct {
	ID          int64     `json:"id"`
	ServerID    string    `json:"server_id"`
	CPUPercent  float64   `json:"cpu_percent"`
	RAMPercent  float64   `json:"ram_percent"`
	DiskPercent float64   `json:"disk_percent"`
	Load1Min    float64   `json:"load_1min"`
	Load5Min    float64   `json:"load_5min"`
	Load15Min   float64   `json:"load_15min"`
	CreatedAt   time.Time `json:"created_at"`
}

// User represents an authenticated administrative user
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // admin, operator, viewer
	CreatedAt    time.Time `json:"created_at"`
}

// AuthRequest handles login payload
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse returns token and user details
type AuthResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	User      User   `json:"user"`
}

// ErrorDiagnostic represents an incident for Advanced Error Analysis
type ErrorDiagnostic struct {
	ID                 int64     `json:"id"`
	IncidentID         string    `json:"incident_id"`
	RequestID          string    `json:"request_id"`
	DomainName         string    `json:"domain_name"`
	ErrorType          string    `json:"error_type"` // PHP_FATAL, HTTP_500, MEMORY_EXHAUSTED, SLOW_QUERY
	Severity           string    `json:"severity"`   // CRITICAL, ERROR, WARNING
	Category           string    `json:"category"`   // Reliability, Performance, Security
	Message            string    `json:"message"`
	File               string    `json:"file"`
	Line               int       `json:"line"`
	StackTrace         string    `json:"stack_trace"`
	ConfidenceScore    float64   `json:"confidence_score"`
	AIRootCause        string    `json:"ai_root_cause"`
	RemediationSteps   []string  `json:"remediation_steps"`
	CreatedAt          time.Time `json:"created_at"`
}

// APIKey represents daemon/SDK secret keys
type APIKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	KeyHash   string    `json:"-"`
	Prefix    string    `json:"prefix"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}


