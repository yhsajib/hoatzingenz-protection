package services

import (
	"fmt"
	"sync"
	"time"
	"strings"

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


func (s *MemoryStore) SetWebsiteDeepDiagnostics(domain string, enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.websites {
		if strings.EqualFold(s.websites[i].DomainName, domain) {
			s.websites[i].DeepDiagnosticsEnabled = enabled
			return true
		}
	}
	return false
}

func (s *MemoryStore) GetWebsiteDeepDiagnostics(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.websites {
		if strings.EqualFold(s.websites[i].DomainName, domain) {
			return s.websites[i].DeepDiagnosticsEnabled
		}
	}
	return false
}

func (s *MemoryStore) UpdateWebsiteStatus(domain string, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.websites {
		if strings.EqualFold(s.websites[i].DomainName, domain) {
			s.websites[i].Status = status
			return true
		}
	}
	return false
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

func (s *MemoryStore) UpdateDatabasePassword(name, newPassword, newURI string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.databases {
		if strings.EqualFold(s.databases[i].Name, name) {
			s.databases[i].Password = newPassword
			s.databases[i].ConnectionURI = newURI
			return true
		}
	}
	return false
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
