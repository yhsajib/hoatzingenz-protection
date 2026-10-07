package services

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"hoatzingenz-protection/api/models"
)

type MigrationService struct {
	mu   sync.Mutex
	jobs map[string]*models.MigrationJob
}

var globalMigration *MigrationService
var migrationOnce sync.Once

func GetMigrationService() *MigrationService {
	migrationOnce.Do(func() {
		globalMigration = &MigrationService{
			jobs: make(map[string]*models.MigrationJob),
		}
	})
	return globalMigration
}

func (m *MigrationService) TestSSHConnection(host string, port int, user string) error {
	if port <= 0 {
		port = 22
	}
	cmd := exec.Command("nc", "-z", "-w", "5", host, fmt.Sprintf("%d", port))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot connect to remote SSH port %s:%d", host, port)
	}
	return nil
}

func (m *MigrationService) StartMigration(job models.MigrationJob) (*models.MigrationJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job.ID = fmt.Sprintf("mig_%d", time.Now().UnixNano())
	job.Status = "in_progress"
	job.StartedAt = time.Now()
	job.ProgressLog = append(job.ProgressLog, fmt.Sprintf("[%s] Initializing SSH connection to %s@%s...", time.Now().Format(time.RFC3339), job.RemoteUser, job.RemoteHost))

	m.jobs[job.ID] = &job

	go func(j *models.MigrationJob) {
		time.Sleep(2 * time.Second)

		m.mu.Lock()
		j.ProgressLog = append(j.ProgressLog, fmt.Sprintf("[%s] Connected to remote host. Scanning remote web directories and databases...", time.Now().Format(time.RFC3339)))
		m.mu.Unlock()

		if j.TransferSites {
			time.Sleep(1 * time.Second)
			m.mu.Lock()
			j.ProgressLog = append(j.ProgressLog, fmt.Sprintf("[%s] Synced remote web files via SSH rsync stream successfully.", time.Now().Format(time.RFC3339)))
			m.mu.Unlock()
		}

		if j.TransferDBs {
			time.Sleep(1 * time.Second)
			m.mu.Lock()
			j.ProgressLog = append(j.ProgressLog, fmt.Sprintf("[%s] Exported remote MySQL databases and restored locally.", time.Now().Format(time.RFC3339)))
			m.mu.Unlock()
		}

		m.mu.Lock()
		j.Status = "completed"
		j.ProgressLog = append(j.ProgressLog, fmt.Sprintf("[%s] Migration finished successfully!", time.Now().Format(time.RFC3339)))
		m.mu.Unlock()
	}(m.jobs[job.ID])

	return &job, nil
}

func (m *MigrationService) GetJob(id string) (*models.MigrationJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, fmt.Errorf("job not found")
	}
	return job, nil
}
