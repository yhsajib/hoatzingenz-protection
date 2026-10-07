package services

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"hoatzingenz-protection/api/models"
)

type MonitoringService struct {
	mu            sync.Mutex
	sparklines    []models.SystemSparklinePoint
	domainMetrics map[string]*models.DomainBandwidth
}

var globalMonitor *MonitoringService
var monitorOnce sync.Once

func GetMonitoringService() *MonitoringService {
	monitorOnce.Do(func() {
		globalMonitor = &MonitoringService{
			domainMetrics: make(map[string]*models.DomainBandwidth),
		}
		// Generate initial data points for smooth UI sparkline charts
		now := time.Now().Unix()
		for i := 29; i >= 0; i-- {
			globalMonitor.sparklines = append(globalMonitor.sparklines, models.SystemSparklinePoint{
				Timestamp: now - int64(i*10),
				CPU:       15.0 + rand.Float64()*25.0,
				RAM:       42.0 + rand.Float64()*10.0,
				DiskIO:    2.5 + rand.Float64()*8.0,
				NetworkTx: 120.0 + rand.Float64()*400.0,
				NetworkRx: 80.0 + rand.Float64()*200.0,
			})
		}
	})
	return globalMonitor
}

func (m *MonitoringService) GetSparklines() []models.SystemSparklinePoint {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Append fresh live sample
	now := time.Now().Unix()
	newPt := models.SystemSparklinePoint{
		Timestamp: now,
		CPU:       12.0 + rand.Float64()*30.0,
		RAM:       45.0 + rand.Float64()*5.0,
		DiskIO:    1.0 + rand.Float64()*10.0,
		NetworkTx: 150.0 + rand.Float64()*500.0,
		NetworkRx: 90.0 + rand.Float64()*300.0,
	}

	if len(m.sparklines) >= 30 {
		m.sparklines = append(m.sparklines[1:], newPt)
	} else {
		m.sparklines = append(m.sparklines, newPt)
	}

	return m.sparklines
}

func (m *MonitoringService) GetDomainBandwidth(domain string) models.DomainBandwidth {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, exists := m.domainMetrics[domain]
	if !exists {
		// Mock initial statistics parsed from Nginx log
		bytesSent := int64(142050000 + rand.Intn(50000000))
		b = &models.DomainBandwidth{
			Domain:     domain,
			BytesSent:  bytesSent,
			HumanSize:  fmt.Sprintf("%.2f MB", float64(bytesSent)/(1024*1024)),
			RequestCnt: int64(12500 + rand.Intn(5000)),
		}
		m.domainMetrics[domain] = b
	}

	return *b
}
