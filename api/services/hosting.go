package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"hoatzingenz-protection/api/models"
)

// ---------------------------------------------------------------------------
// Basics
// ---------------------------------------------------------------------------

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$`)
var identRe = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)
var cronScheduleRe = regexp.MustCompile(`^[0-9*/,\-]+( [0-9*/,\-]+){4}$`)
var nonAlnumRe = regexp.MustCompile(`[^a-zA-Z0-9]`)

// WebRootBase returns the parent directory that holds every site (<base>/<domain>).
func WebRootBase() string {
	if v := os.Getenv("HZ_WEB_ROOT"); v != "" {
		return v
	}
	return "/var/www/html"
}

// ValidDomain validates a hostname used for a site.
func ValidDomain(d string) bool {
	return len(d) > 0 && len(d) <= 253 && !strings.Contains(d, "..") && domainRe.MatchString(d)
}

func SiteRootDir(domain string) string { return filepath.Join(WebRootBase(), domain) }

// ValidIdent validates database / user identifiers.
func ValidIdent(s string) bool { return identRe.MatchString(s) }

// RandomString returns a cryptographically random alphanumeric string.
func RandomString(n int) string {
	const chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i := range out {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		out[i] = chars[idx.Int64()]
	}
	return string(out)
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s == "" {
			s = err.Error()
		}
		return s, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), s)
	}
	return s, nil
}

// Live reports whether real system changes can be applied (root + nginx present).
func (v *VHostAutomationEngine) Live() bool {
	return !v.DryRun && os.Geteuid() == 0
}

func (v *VHostAutomationEngine) liveReason() string {
	switch {
	case v.DryRun:
		return "nginx is not installed (" + v.NginxAvailableDir + " not found)"
	case os.Geteuid() != 0:
		return "the panel is not running as root"
	}
	return ""
}

// ---------------------------------------------------------------------------
// System status
// ---------------------------------------------------------------------------

type SystemCheck struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Detail    string `json:"detail,omitempty"`
}

type SystemStatus struct {
	Live        bool          `json:"live"`
	Reason      string        `json:"reason,omitempty"`
	WebRoot     string        `json:"web_root"`
	PHPVersions []string      `json:"php_versions"`
	Checks      []SystemCheck `json:"checks"`
}

// InstalledPHPVersions lists PHP versions that have php-fpm installed.
func InstalledPHPVersions() []string {
	matches, _ := filepath.Glob("/etc/php/*/fpm/pool.d")
	var vers []string
	for _, m := range matches {
		vers = append(vers, filepath.Base(filepath.Dir(filepath.Dir(m))))
	}
	sort.Strings(vers)
	return vers
}

func (v *VHostAutomationEngine) Status() SystemStatus {
	st := SystemStatus{Live: v.Live(), Reason: v.liveReason(), WebRoot: WebRootBase(), PHPVersions: InstalledPHPVersions()}
	check := func(name, bin string) {
		p, err := exec.LookPath(bin)
		st.Checks = append(st.Checks, SystemCheck{Name: name, Installed: err == nil, Detail: p})
	}
	check("nginx", "nginx")
	check("mysql/mariadb", "mysql")
	check("certbot", "certbot")
	check("php-fpm", "php")
	st.Checks = append(st.Checks, SystemCheck{Name: "php-fpm pools", Installed: len(st.PHPVersions) > 0, Detail: strings.Join(st.PHPVersions, ", ")})
	return st
}

// ---------------------------------------------------------------------------
// MySQL / MariaDB
// ---------------------------------------------------------------------------

func sqlStr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `''`)
}

func (v *VHostAutomationEngine) mysql(query string) (string, error) {
	return runCmd(60*time.Second, "mysql", "-u", "root", "-N", "-B", "-e", query)
}

// MySQLCreate creates a database and a user with full rights on it.
func (v *VHostAutomationEngine) MySQLCreate(name, user, pass string) error {
	if !ValidIdent(name) || !ValidIdent(user) {
		return fmt.Errorf("invalid database or user name (letters, digits, underscore; max 32)")
	}
	if len(pass) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if !v.Live() {
		return fmt.Errorf("cannot create database: %s", v.liveReason())
	}
	if _, err := exec.LookPath("mysql"); err != nil {
		return fmt.Errorf("MariaDB/MySQL client not installed (apt install mariadb-server)")
	}
	q := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "+
		"CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s'; "+
		"ALTER USER '%s'@'localhost' IDENTIFIED BY '%s'; "+
		"GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;",
		name, user, sqlStr(pass), user, sqlStr(pass), name, user)
	_, err := v.mysql(q)
	return err
}

func (v *VHostAutomationEngine) MySQLDrop(name, user string) error {
	if !ValidIdent(name) || (user != "" && !ValidIdent(user)) {
		return fmt.Errorf("invalid database or user name")
	}
	if !v.Live() {
		return fmt.Errorf("cannot drop database: %s", v.liveReason())
	}
	q := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", name)
	if user != "" {
		q += fmt.Sprintf(" DROP USER IF EXISTS '%s'@'localhost';", user)
	}
	q += " FLUSH PRIVILEGES;"
	_, err := v.mysql(q)
	return err
}

// MySQLSizeMB returns the on-disk size of a database in MB.
func (v *VHostAutomationEngine) MySQLSizeMB(name string) float64 {
	if !v.Live() || !ValidIdent(name) {
		return 0
	}
	out, err := v.mysql(fmt.Sprintf("SELECT ROUND(COALESCE(SUM(data_length+index_length),0)/1024/1024,2) FROM information_schema.tables WHERE table_schema='%s';", name))
	if err != nil {
		return 0
	}
	var f float64
	fmt.Sscanf(strings.TrimSpace(out), "%f", &f)
	return f
}

// ---------------------------------------------------------------------------
// WordPress
// ---------------------------------------------------------------------------

// InstallWordPress downloads the latest WordPress release and extracts it into root,
// never overwriting existing files.
func InstallWordPress(root string) error {
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get("https://wordpress.org/latest.tar.gz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "wordpress/")
		if name == "" || strings.HasPrefix(name, "wordpress") {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if _, err := os.Stat(target); err == nil {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(hdr.Mode)&0777|0600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

func phpEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `\'`)
}

// WriteWPConfig writes a wp-config.php with real random salts (no-op if it exists).
func WriteWPConfig(root string, site models.Website) error {
	path := filepath.Join(root, "wp-config.php")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	var salts strings.Builder
	for _, k := range []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"} {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		fmt.Fprintf(&salts, "define( '%s', '%s' );\n", k, hex.EncodeToString(b))
	}
	host := site.DBHost
	if host == "" {
		host = "localhost"
	}
	content := fmt.Sprintf(`<?php
// WordPress wp-config.php generated by HoatzinGenz for %s
define( 'DB_NAME', '%s' );
define( 'DB_USER', '%s' );
define( 'DB_PASSWORD', '%s' );
define( 'DB_HOST', '%s' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

%s
$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
define( 'FS_METHOD', 'direct' );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`, site.DomainName, phpEscape(site.DBName), phpEscape(site.DBUser), phpEscape(site.DBPass), phpEscape(host), salts.String())
	return os.WriteFile(path, []byte(content), 0640)
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

func needsPHP(siteType string) bool {
	switch siteType {
	case "wordpress", "laravel", "php":
		return true
	}
	return false
}

func fpmService(ver string) string { return "php" + ver + "-fpm" }

func vhostFiles(v *VHostAutomationEngine, domain string) (avail, enabled, pool, unit string) {
	return filepath.Join(v.NginxAvailableDir, domain+".conf"),
		filepath.Join(v.NginxEnabledDir, domain+".conf"),
		"", "/etc/systemd/system/hz-site-" + nonAlnumRe.ReplaceAllString(domain, "-") + ".service"
}

// Provision creates everything a site needs on this server. It mutates site
// (document root, generated database credentials) and returns a human readable log.
func (v *VHostAutomationEngine) Provision(site *models.Website) ([]string, error) {
	var steps []string
	logf := func(format string, a ...interface{}) {
		m := fmt.Sprintf(format, a...)
		steps = append(steps, m)
		log.Printf("[PROVISION %s] %s", site.DomainName, m)
	}

	site.DocumentRoot = SiteRootDir(site.DomainName)
	if site.PHPVersion == "" {
		site.PHPVersion = "8.3"
	}
	if site.DBHost == "" {
		site.DBHost = "localhost"
	}
	if needsPHP(site.SiteType) && site.SiteType != "php" {
		if site.DBName == "" {
			site.DBName = "db_" + strings.ReplaceAll(strings.ReplaceAll(site.DomainName, ".", "_"), "-", "_")
			if len(site.DBName) > 32 {
				site.DBName = site.DBName[:32]
			}
		}
		if site.DBUser == "" {
			site.DBUser = site.DBName
			if len(site.DBUser) > 28 {
				site.DBUser = site.DBUser[:28]
			}
			site.DBUser += "_u"
		}
		if site.DBPass == "" {
			site.DBPass = RandomString(24)
		}
	}

	if !v.Live() {
		if err := os.MkdirAll(site.DocumentRoot, 0755); err == nil {
			logf("Created site directory %s", site.DocumentRoot)
		}
		logf("DRY RUN: system provisioning skipped because %s. The site was only recorded in the panel.", v.liveReason())
		return steps, nil
	}

	fpmPoolDir := ""
	if needsPHP(site.SiteType) {
		fpmPoolDir = filepath.Join("/etc/php", site.PHPVersion, "fpm", "pool.d")
		if _, err := os.Stat(fpmPoolDir); err != nil {
			return steps, fmt.Errorf("PHP %s FPM is not installed (apt install php%s-fpm php%s-mysql php%s-curl php%s-xml php%s-mbstring php%s-zip php%s-gd)",
				site.PHPVersion, site.PHPVersion, site.PHPVersion, site.PHPVersion, site.PHPVersion, site.PHPVersion, site.PHPVersion, site.PHPVersion)
		}
	}

	if err := os.MkdirAll(site.DocumentRoot, 0755); err != nil {
		return steps, fmt.Errorf("create site directory: %w", err)
	}
	logf("Created site directory %s", site.DocumentRoot)

	if site.DBName != "" && (site.SiteType == "wordpress" || site.SiteType == "laravel") {
		if err := v.MySQLCreate(site.DBName, site.DBUser, site.DBPass); err != nil {
			return steps, fmt.Errorf("create database: %w", err)
		}
		logf("Created MariaDB database %s with user %s", site.DBName, site.DBUser)
	}

	switch site.SiteType {
	case "wordpress":
		if err := InstallWordPress(site.DocumentRoot); err != nil {
			return steps, fmt.Errorf("install WordPress: %w", err)
		}
		logf("Installed WordPress core files")
		if err := WriteWPConfig(site.DocumentRoot, *site); err != nil {
			return steps, fmt.Errorf("write wp-config.php: %w", err)
		}
		logf("Generated wp-config.php with unique salts")
	case "laravel", "php":
		if _, err := os.Stat(filepath.Join(site.DocumentRoot, "index.php")); err != nil && site.SiteType == "php" {
			_ = os.WriteFile(filepath.Join(site.DocumentRoot, "index.php"), []byte("<?php phpinfo();\n"), 0644)
		}
	case "static":
		idx := filepath.Join(site.DocumentRoot, "index.html")
		if _, err := os.Stat(idx); err != nil {
			_ = os.WriteFile(idx, []byte("<!DOCTYPE html><html><head><title>"+site.DomainName+"</title></head><body><h1>"+site.DomainName+"</h1><p>Managed by HoatzinGenz.</p></body></html>\n"), 0644)
		}
	}

	_, _ = runCmd(2*time.Minute, "chown", "-R", "www-data:www-data", site.DocumentRoot)
	logf("Set ownership www-data:www-data")

	if fpmPoolDir != "" {
		tmpl, _ := template.New("fpm").Parse(fpmPoolTemplate)
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, site); err != nil {
			return steps, err
		}
		poolPath := filepath.Join(fpmPoolDir, site.DomainName+".conf")
		if err := os.WriteFile(poolPath, buf.Bytes(), 0644); err != nil {
			return steps, fmt.Errorf("write FPM pool: %w", err)
		}
		if out, err := runCmd(time.Minute, "systemctl", "reload", fpmService(site.PHPVersion)); err != nil {
			_ = os.Remove(poolPath)
			return steps, fmt.Errorf("reload %s failed: %s", fpmService(site.PHPVersion), out)
		}
		logf("Created PHP-FPM pool %s and reloaded %s", poolPath, fpmService(site.PHPVersion))
	}

	vhost := v.GenerateNginxConfig(*site)
	avail := filepath.Join(v.NginxAvailableDir, site.DomainName+".conf")
	enabled := filepath.Join(v.NginxEnabledDir, site.DomainName+".conf")
	if err := os.WriteFile(avail, []byte(vhost), 0644); err != nil {
		return steps, fmt.Errorf("write nginx vhost: %w", err)
	}
	_ = os.Remove(enabled)
	if err := os.Symlink(avail, enabled); err != nil {
		return steps, fmt.Errorf("enable nginx vhost: %w", err)
	}
	if out, err := runCmd(30*time.Second, "nginx", "-t"); err != nil {
		_ = os.Remove(enabled)
		_ = os.Remove(avail)
		return steps, fmt.Errorf("nginx config test failed: %s", out)
	}
	if out, err := runCmd(30*time.Second, "systemctl", "reload", "nginx"); err != nil {
		return steps, fmt.Errorf("nginx reload failed: %s", out)
	}
	logf("Created nginx vhost %s and reloaded nginx", avail)

	if site.SiteType == "nodejs" || site.SiteType == "python" {
		unitContent := v.GenerateSystemdConfig(*site)
		if unitContent != "" {
			_, _, _, unit := vhostFiles(v, site.DomainName)
			if err := os.WriteFile(unit, []byte(unitContent), 0644); err == nil {
				_, _ = runCmd(30*time.Second, "systemctl", "daemon-reload")
				name := filepath.Base(unit)
				if _, err := runCmd(30*time.Second, "systemctl", "enable", name); err == nil {
					logf("Installed systemd service %s (upload your app, then start it)", name)
				}
			}
		}
	}

	return steps, nil
}

// Deprovision removes vhost, pool, service and cron entries. Files/DB are removed on request.
func (v *VHostAutomationEngine) Deprovision(site models.Website, removeFiles, dropDB bool) []string {
	var steps []string
	d := site.DomainName
	if !v.Live() {
		return []string{"DRY RUN: nothing removed from the system (" + v.liveReason() + ")"}
	}
	avail, enabled, _, unit := vhostFiles(v, d)
	_ = os.Remove(enabled)
	_ = os.Remove(avail)
	steps = append(steps, "Removed nginx vhost")
	for _, p := range filepath.SplitList(strings.Join(globPools(d), string(os.PathListSeparator))) {
		if p != "" {
			_ = os.Remove(p)
		}
	}
	if _, err := os.Stat(unit); err == nil {
		_, _ = runCmd(30*time.Second, "systemctl", "disable", "--now", filepath.Base(unit))
		_ = os.Remove(unit)
		_, _ = runCmd(30*time.Second, "systemctl", "daemon-reload")
	}
	_ = os.Remove(cronFile(d))
	if _, err := os.Stat("/etc/letsencrypt/live/" + d); err == nil {
		_, _ = runCmd(time.Minute, "certbot", "delete", "--cert-name", d, "--non-interactive")
	}
	if site.PHPVersion != "" {
		_, _ = runCmd(time.Minute, "systemctl", "reload", fpmService(site.PHPVersion))
	}
	_, _ = runCmd(30*time.Second, "systemctl", "reload", "nginx")
	if dropDB && site.DBName != "" {
		if err := v.MySQLDrop(site.DBName, site.DBUser); err == nil {
			steps = append(steps, "Dropped database "+site.DBName)
		}
	}
	if removeFiles && ValidDomain(d) {
		root := SiteRootDir(d)
		if root != WebRootBase() && strings.HasPrefix(root, WebRootBase()+string(os.PathSeparator)) {
			_ = os.RemoveAll(root)
			steps = append(steps, "Deleted "+root)
		}
	}
	return steps
}

func globPools(domain string) []string {
	m, _ := filepath.Glob("/etc/php/*/fpm/pool.d/" + domain + ".conf")
	return m
}

// ---------------------------------------------------------------------------
// SSL (Let's Encrypt via certbot)
// ---------------------------------------------------------------------------

type CertInfo struct {
	Issuer    string `json:"issuer"`
	ExpiresAt string `json:"expires_at"`
	DaysLeft  int    `json:"days_left"`
}

func ReadCertInfo(domain string) (*CertInfo, error) {
	data, err := os.ReadFile("/etc/letsencrypt/live/" + domain + "/fullchain.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &CertInfo{
		Issuer:    cert.Issuer.CommonName,
		ExpiresAt: cert.NotAfter.Format("2006-01-02 15:04:05"),
		DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
	}, nil
}

func (v *VHostAutomationEngine) IssueSSL(domain, email string) (string, error) {
	if !ValidDomain(domain) {
		return "", fmt.Errorf("invalid domain")
	}
	if !v.Live() {
		return "", fmt.Errorf("cannot issue certificate: %s", v.liveReason())
	}
	if _, err := exec.LookPath("certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed (apt install certbot python3-certbot-nginx)")
	}
	args := []string{"--nginx", "-d", domain, "-d", "www." + domain, "--non-interactive", "--agree-tos", "--redirect"}
	if email != "" {
		args = append(args, "-m", email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	return runCmd(5*time.Minute, "certbot", args...)
}

func (v *VHostAutomationEngine) RenewSSL(domain string) (string, error) {
	if !v.Live() {
		return "", fmt.Errorf("cannot renew: %s", v.liveReason())
	}
	if _, err := exec.LookPath("certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed")
	}
	return runCmd(5*time.Minute, "certbot", "renew", "--cert-name", domain, "--non-interactive")
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

func cronFile(domain string) string {
	return "/etc/cron.d/hz_" + nonAlnumRe.ReplaceAllString(domain, "_")
}

func ValidCronSchedule(s string) bool { return cronScheduleRe.MatchString(strings.TrimSpace(s)) }

// WriteCron installs the active jobs of a site into /etc/cron.d.
func (v *VHostAutomationEngine) WriteCron(domain string, jobs []models.CronJob) error {
	if !v.Live() {
		return nil
	}
	var b strings.Builder
	b.WriteString("# Managed by HoatzinGenz for " + domain + "\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	count := 0
	for _, j := range jobs {
		if !j.Active {
			continue
		}
		fmt.Fprintf(&b, "%s www-data %s\n", strings.TrimSpace(j.Schedule), strings.ReplaceAll(strings.ReplaceAll(j.Command, "\r", " "), "\n", " "))
		count++
	}
	if count == 0 {
		_ = os.Remove(cronFile(domain))
		return nil
	}
	return os.WriteFile(cronFile(domain), []byte(b.String()), 0644)
}

// ---------------------------------------------------------------------------
// Services & site actions
// ---------------------------------------------------------------------------

func unitActive(unit string) (bool, bool) {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	if state == "active" {
		return true, true
	}
	// installed?
	if o, _ := exec.Command("systemctl", "cat", unit).Output(); len(o) > 0 {
		return false, true
	}
	return false, false
}

func (v *VHostAutomationEngine) managedUnits() []struct{ Label, Unit string } {
	units := []struct{ Label, Unit string }{
		{"Nginx HTTP Server", "nginx"},
		{"MariaDB / MySQL Server", "mariadb"},
		{"MySQL Server", "mysql"},
		{"Redis", "redis-server"},
		{"PostgreSQL", "postgresql"},
		{"Fail2ban", "fail2ban"},
		{"Cron", "cron"},
		{"SSH Server", "ssh"},
	}
	for _, ver := range InstalledPHPVersions() {
		units = append(units, struct{ Label, Unit string }{"PHP-FPM " + ver, fpmService(ver)})
	}
	return units
}

func (v *VHostAutomationEngine) ListServices() []models.SystemService {
	list := []models.SystemService{}
	for _, u := range v.managedUnits() {
		active, installed := unitActive(u.Unit)
		if !installed {
			continue
		}
		s := models.SystemService{Name: u.Label, Engine: u.Unit, Status: "stopped"}
		if active {
			s.Status = "running"
			if out, err := exec.Command("systemctl", "show", "-p", "MemoryCurrent", "--value", u.Unit).Output(); err == nil {
				var b float64
				if _, e := fmt.Sscanf(strings.TrimSpace(string(out)), "%f", &b); e == nil {
					s.MemoryMB = b / 1024 / 1024
				}
			}
			if out, err := exec.Command("systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", u.Unit).Output(); err == nil {
				ts := strings.TrimSpace(string(out))
				if t, e := time.Parse("Mon 2006-01-02 15:04:05 MST", ts); e == nil {
					s.Uptime = time.Since(t).Round(time.Minute).String()
				} else {
					s.Uptime = ts
				}
			}
		}
		list = append(list, s)
	}
	return list
}

func (v *VHostAutomationEngine) ServiceAction(unit, action string) (string, error) {
	if !v.Live() {
		return "", fmt.Errorf("cannot manage services: %s", v.liveReason())
	}
	switch action {
	case "start", "stop", "restart", "reload":
	default:
		return "", fmt.Errorf("unsupported action")
	}
	allowed := false
	for _, u := range v.managedUnits() {
		if u.Unit == unit {
			allowed = true
		}
	}
	if !allowed {
		return "", fmt.Errorf("unknown service")
	}
	return runCmd(time.Minute, "systemctl", action, unit)
}

func (v *VHostAutomationEngine) SiteAction(site models.Website, action string) (string, error) {
	if !v.Live() {
		return "", fmt.Errorf("cannot run '%s': %s", action, v.liveReason())
	}
	switch action {
	case "reload_nginx":
		return runCmd(30*time.Second, "systemctl", "reload", "nginx")
	case "reload_fpm", "restart_fpm":
		verb := "reload"
		if action == "restart_fpm" {
			verb = "restart"
		}
		return runCmd(30*time.Second, "systemctl", verb, fpmService(site.PHPVersion))
	case "purge_cache":
		dir := "/var/cache/nginx/" + site.DomainName
		if _, err := os.Stat(dir); err != nil {
			return "No nginx cache directory for this site; nothing to purge", nil
		}
		if err := os.RemoveAll(dir); err != nil {
			return "", err
		}
		_ = os.MkdirAll(dir, 0755)
		_, _ = runCmd(30*time.Second, "systemctl", "reload", "nginx")
		return "Cache purged", nil
	case "ssl_renew":
		return v.RenewSSL(site.DomainName)
	case "fix_permissions":
		_, err := runCmd(5*time.Minute, "chown", "-R", "www-data:www-data", SiteRootDir(site.DomainName))
		return "Ownership reset to www-data", err
	}
	return "", fmt.Errorf("unknown action")
}

// TailLog returns the last n lines of a site log.
func TailLog(domain, kind string, n int) (string, error) {
	var path string
	switch kind {
	case "access":
		path = "/var/log/nginx/" + domain + "_access.log"
	case "error":
		path = "/var/log/nginx/" + domain + "_error.log"
	case "fpm":
		m, _ := filepath.Glob("/var/log/php*-fpm.log")
		if len(m) == 0 {
			return "", fmt.Errorf("no php-fpm log found")
		}
		path = m[0]
	default:
		return "", fmt.Errorf("unknown log type")
	}
	if n <= 0 || n > 2000 {
		n = 200
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()
	const maxRead = 512 * 1024
	start := int64(0)
	if size > maxRead {
		start = size - maxRead
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}
