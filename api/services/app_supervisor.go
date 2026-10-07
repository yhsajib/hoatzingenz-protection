package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"hoatzingenz-protection/api/models"
)

type AppSupervisor struct {
	mu     sync.Mutex
	apps   map[string]*models.AppSupervisorConfig
	engine *VHostAutomationEngine
}

var globalSupervisor *AppSupervisor
var supervisorOnce sync.Once

func GetAppSupervisor(vhostEng *VHostAutomationEngine) *AppSupervisor {
	supervisorOnce.Do(func() {
		globalSupervisor = &AppSupervisor{
			apps:   make(map[string]*models.AppSupervisorConfig),
			engine: vhostEng,
		}
	})
	return globalSupervisor
}

func (s *AppSupervisor) DeployApp(cfg models.AppSupervisorConfig) (*models.AppSupervisorConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.Domain == "" || cfg.Port <= 0 {
		return nil, fmt.Errorf("domain and valid port are required")
	}

	cfg.ID = fmt.Sprintf("app_%d", time.Now().UnixNano())
	cfg.CreatedAt = time.Now()
	cfg.Status = "running"

	// 1. Generate Nginx reverse proxy config
	nginxConf := fmt.Sprintf(`server {
    listen 80;
    server_name %s www.%s;

    location / {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
`, cfg.Domain, cfg.Domain, cfg.Port)

	vhostPath := filepath.Join(s.engine.NginxAvailableDir, cfg.Domain+".conf")
	if err := os.WriteFile(vhostPath, []byte(nginxConf), 0644); err == nil {
		symlinkPath := filepath.Join(s.engine.NginxEnabledDir, cfg.Domain+".conf")
		os.Remove(symlinkPath)
		os.Symlink(vhostPath, symlinkPath)
		exec.Command("systemctl", "reload", "nginx").Run()
	}

	// 2. Launch process via Systemd or nohup if available
	if cfg.AppType == "nodejs" {
		cmdStr := fmt.Sprintf("PORT=%d node %s", cfg.Port, cfg.EntryFile)
		cmd := exec.Command("bash", "-c", fmt.Sprintf("cd %s && nohup %s > app.log 2>&1 & echo $!", cfg.WorkDir, cmdStr))
		out, err := cmd.Output()
		if err == nil {
			pidStr := strings.TrimSpace(string(out))
			pid, _ := strconv.Atoi(pidStr)
			cfg.ProcessID = pid
		}
	} else if cfg.AppType == "python" {
		cmdStr := fmt.Sprintf("gunicorn --bind 127.0.0.1:%d %s:app", cfg.Port, strings.TrimSuffix(cfg.EntryFile, ".py"))
		cmd := exec.Command("bash", "-c", fmt.Sprintf("cd %s && nohup %s > app.log 2>&1 & echo $!", cfg.WorkDir, cmdStr))
		out, err := cmd.Output()
		if err == nil {
			pidStr := strings.TrimSpace(string(out))
			pid, _ := strconv.Atoi(pidStr)
			cfg.ProcessID = pid
		}
	}

	s.apps[cfg.ID] = &cfg
	return &cfg, nil
}

func (s *AppSupervisor) ListApps() []*models.AppSupervisorConfig {
	s.mu.Lock()
	defer s.mu.Unlock()

	var list []*models.AppSupervisorConfig
	for _, app := range s.apps {
		list = append(list, app)
	}
	return list
}

func (s *AppSupervisor) StopApp(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	app, exists := s.apps[id]
	if !exists {
		return fmt.Errorf("app not found")
	}

	if app.ProcessID > 0 {
		exec.Command("kill", "-9", fmt.Sprintf("%d", app.ProcessID)).Run()
	}
	app.Status = "stopped"
	return nil
}
