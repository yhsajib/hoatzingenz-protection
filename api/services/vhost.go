package services

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"hoatzingenz-protection/api/models"
)

type VHostAutomationEngine struct {
	NginxAvailableDir string
	NginxEnabledDir   string
	FPMPoolDir        string
	DryRun            bool
}

func NewVHostAutomationEngine(nginxAvailable, nginxEnabled, fpmPool string) *VHostAutomationEngine {
	dryRun := false
	if _, err := os.Stat(nginxAvailable); os.IsNotExist(err) {
		dryRun = true
	}

	return &VHostAutomationEngine{
		NginxAvailableDir: nginxAvailable,
		NginxEnabledDir:   nginxEnabled,
		FPMPoolDir:        fpmPool,
		DryRun:            dryRun,
	}
}

const nginxWordPressTemplate = `server {
    listen 80;
    listen [::]:80;
    server_name {{.DomainName}} www.{{.DomainName}};
    root {{.DocumentRoot}};
    index index.php index.html index.htm;

    client_max_body_size 100M;
    access_log /var/log/nginx/{{.DomainName}}_access.log;
    error_log /var/log/nginx/{{.DomainName}}_error.log;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass unix:/run/php/php{{.PHPVersion}}-fpm-{{.DomainName}}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~ /\.ht {
        deny all;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }
}
`

const nginxLaravelTemplate = `server {
    listen 80;
    listen [::]:80;
    server_name {{.DomainName}} www.{{.DomainName}};
    root {{.DocumentRoot}}/public;
    index index.php index.html;

    client_max_body_size 100M;
    access_log /var/log/nginx/{{.DomainName}}_access.log;
    error_log /var/log/nginx/{{.DomainName}}_error.log;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php{{.PHPVersion}}-fpm-{{.DomainName}}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~ /\.ht {
        deny all;
    }
}
`

const nginxNodeJSTemplate = `server {
    listen 80;
    listen [::]:80;
    server_name {{.DomainName}} www.{{.DomainName}};

    access_log /var/log/nginx/{{.DomainName}}_access.log;
    error_log /var/log/nginx/{{.DomainName}}_error.log;

    location / {
        proxy_pass http://127.0.0.1:{{if .AppPort}}{{.AppPort}}{{else}}3000{{end}};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`

const nginxPythonTemplate = `server {
    listen 80;
    listen [::]:80;
    server_name {{.DomainName}} www.{{.DomainName}};

    access_log /var/log/nginx/{{.DomainName}}_access.log;
    error_log /var/log/nginx/{{.DomainName}}_error.log;

    location / {
        proxy_pass http://127.0.0.1:{{if .AppPort}}{{.AppPort}}{{else}}8000{{end}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias {{.DocumentRoot}}/static/;
    }
}
`

const nginxStaticTemplate = `server {
    listen 80;
    listen [::]:80;
    server_name {{.DomainName}} www.{{.DomainName}};
    root {{.DocumentRoot}};
    index index.html index.htm;

    access_log /var/log/nginx/{{.DomainName}}_access.log;
    error_log /var/log/nginx/{{.DomainName}}_error.log;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
`

const fpmPoolTemplate = `[{{.DomainName}}]
user = www-data
group = www-data
listen = /run/php/php{{.PHPVersion}}-fpm-{{.DomainName}}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 20
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

{{if .PHPSettings.MemoryLimit}}php_admin_value[memory_limit] = {{.PHPSettings.MemoryLimit}}{{end}}
{{if .PHPSettings.UploadMaxFilesize}}php_admin_value[upload_max_filesize] = {{.PHPSettings.UploadMaxFilesize}}{{end}}
{{if .PHPSettings.MaxExecutionTime}}php_admin_value[max_execution_time] = {{.PHPSettings.MaxExecutionTime}}{{end}}
`

func (v *VHostAutomationEngine) ProvisionWebsite(site models.Website) error {
	log.Printf("[AUTOMATION] Provisioning virtual host for domain: %s (Type: %s, PHP: %s)", site.DomainName, site.SiteType, site.PHPVersion)

	if !v.DryRun {
		if err := os.MkdirAll(site.DocumentRoot, 0755); err != nil {
			log.Printf("[WARN] Failed to create document root %s: %v", site.DocumentRoot, err)
		}
	}

	var tmplStr string
	switch site.SiteType {
	case "laravel":
		tmplStr = nginxLaravelTemplate
	case "nodejs":
		tmplStr = nginxNodeJSTemplate
	case "python":
		tmplStr = nginxPythonTemplate
	case "static":
		tmplStr = nginxStaticTemplate
	default:
		tmplStr = nginxWordPressTemplate
	}

	tmpl, err := template.New("vhost").Parse(tmplStr)
	if err != nil {
		return fmt.Errorf("failed to parse vhost template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, site); err != nil {
		return fmt.Errorf("failed to execute vhost template: %w", err)
	}

	if v.DryRun {
		log.Printf("[INFO] [DRY RUN] Generated Nginx VHost config for %s:\n%s", site.DomainName, buf.String())
		return nil
	}

	vhostPath := filepath.Join(v.NginxAvailableDir, site.DomainName+".conf")
	if err := os.WriteFile(vhostPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write vhost config file: %w", err)
	}

	symlinkPath := filepath.Join(v.NginxEnabledDir, site.DomainName+".conf")
	_ = os.Remove(symlinkPath)
	if err := os.Symlink(vhostPath, symlinkPath); err != nil {
		log.Printf("[WARN] Failed to create vhost symlink: %v", err)
	}

	if site.SiteType == "wordpress" || site.SiteType == "laravel" {
		fpmTmpl, _ := template.New("fpm").Parse(fpmPoolTemplate)
		var fpmBuf bytes.Buffer
		_ = fpmTmpl.Execute(&fpmBuf, site)

		fpmPath := filepath.Join(v.FPMPoolDir, site.DomainName+".conf")
		if err := os.WriteFile(fpmPath, fpmBuf.Bytes(), 0644); err == nil {
			log.Printf("[INFO] Created FPM pool config: %s", fpmPath)
			_ = exec.Command("systemctl", "reload", "php"+site.PHPVersion+"-fpm").Run()
		}
	}

	cmdTest := exec.Command("nginx", "-t")
	if err := cmdTest.Run(); err == nil {
		_ = exec.Command("systemctl", "reload", "nginx").Run()
		log.Printf("[INFO] Successfully reloaded Nginx for %s", site.DomainName)
	} else {
		log.Printf("[WARN] Nginx configuration test failed after provision: %v", err)
	}

	return nil
}

func (v *VHostAutomationEngine) GenerateNginxConfig(site models.Website) string {
	var tmplStr string
	switch site.SiteType {
	case "laravel":
		tmplStr = nginxLaravelTemplate
	case "nodejs":
		tmplStr = nginxNodeJSTemplate
	case "python":
		tmplStr = nginxPythonTemplate
	case "static":
		tmplStr = nginxStaticTemplate
	default:
		tmplStr = nginxWordPressTemplate
	}

	tmpl, err := template.New("vhost").Parse(tmplStr)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, site)
	return buf.String()
}

func (v *VHostAutomationEngine) GenerateFPMPoolConfig(site models.Website) string {
	if site.SiteType != "wordpress" && site.SiteType != "laravel" {
		return ""
	}
	tmpl, err := template.New("fpm").Parse(fpmPoolTemplate)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, site)
	return buf.String()
}

func (v *VHostAutomationEngine) GenerateEnvConfig(site models.Website) string {
	switch site.SiteType {
	case "wordpress":
		return fmt.Sprintf(`<?php
// WordPress wp-config.php generated for %s
define( 'DB_NAME', '%s' );
define( 'DB_USER', '%s' );
define( 'DB_PASSWORD', '%s' );
define( 'DB_HOST', '%s' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'put-your-unique-phrase-here' );
define( 'SECURE_AUTH_KEY',  'put-your-unique-phrase-here' );
define( 'LOGGED_IN_KEY',    'put-your-unique-phrase-here' );
define( 'NONCE_KEY',        'put-your-unique-phrase-here' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`, site.DomainName, site.DBName, site.DBUser, site.DBPass, site.DBHost)

	case "laravel":
		return fmt.Sprintf(`APP_NAME="%s"
APP_ENV=production
APP_KEY=%s
APP_DEBUG=false
APP_URL=https://%s

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=%s
DB_PORT=3306
DB_DATABASE=%s
DB_USERNAME=%s
DB_PASSWORD=%s

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=file
SESSION_LIFETIME=120
`, site.SiteTitle, site.AppKey, site.DomainName, site.DBHost, site.DBName, site.DBUser, site.DBPass)

	case "nodejs":
		return fmt.Sprintf(`PORT=%d
NODE_ENV=production
DOMAIN_NAME=%s
DB_HOST=%s
DB_DATABASE=%s
DB_USERNAME=%s
DB_PASSWORD=%s
`, site.AppPort, site.DomainName, site.DBHost, site.DBName, site.DBUser, site.DBPass)

	case "python":
		return fmt.Sprintf(`PORT=%d
ENVIRONMENT=production
ALLOWED_HOSTS=%s,localhost,127.0.0.1
SECRET_KEY=secret-production-key-generate-random
`, site.AppPort, site.DomainName)

	default:
		return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>%s</title>
</head>
<body>
  <h1>Production Ready Host - %s</h1>
  <p>Managed by HoatzinGenz Protection Server Panel</p>
</body>
</html>
`, site.DomainName, site.DomainName)
	}
}

func (v *VHostAutomationEngine) GenerateSystemdConfig(site models.Website) string {
	if site.SiteType == "nodejs" {
		script := site.EntryScript
		if script == "" {
			script = "app.js"
		}
		return fmt.Sprintf(`[Unit]
Description=%s Node.js Daemon Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=%s
ExecStart=/usr/bin/node %s
Restart=always
RestartSec=5
Environment=NODE_ENV=production PORT=%d

[Install]
WantedBy=multi-user.target
`, site.DomainName, site.DocumentRoot, script, site.AppPort)
	}

	if site.SiteType == "python" {
		return fmt.Sprintf(`[Unit]
Description=%s Python WSGI/ASGI Daemon Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=%s
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind 127.0.0.1:%d app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, site.DomainName, site.DocumentRoot, site.AppPort)
	}

	return ""
}

func (v *VHostAutomationEngine) GenerateDeployScript(site models.Website) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
# Production Deployment Script for %s
set -e

echo "[1/4] Preparing site document root directory..."
sudo mkdir -p %s
sudo chown -R www-data:www-data %s
sudo chmod -R 755 %s

echo "[2/4] Testing Nginx virtual host configuration..."
sudo nginx -t

echo "[3/4] Reloading web server daemon..."
sudo systemctl reload nginx

echo "[4/4] Provisioning completed successfully for %s!"
`, site.DomainName, site.DocumentRoot, site.DocumentRoot, site.DocumentRoot, site.DomainName)
}

func (v *VHostAutomationEngine) DeprovisionWebsite(domainName string) error {
	log.Printf("[AUTOMATION] Deprovisioning domain: %s", domainName)
	if v.DryRun {
		log.Printf("[INFO] [DRY RUN] Deprovisioned vhost for %s", domainName)
		return nil
	}

	vhostPath := filepath.Join(v.NginxAvailableDir, domainName+".conf")
	symlinkPath := filepath.Join(v.NginxEnabledDir, domainName+".conf")
	fpmPath := filepath.Join(v.FPMPoolDir, domainName+".conf")

	_ = os.Remove(vhostPath)
	_ = os.Remove(symlinkPath)
	_ = os.Remove(fpmPath)

	_ = exec.Command("systemctl", "reload", "nginx").Run()
	return nil
}


