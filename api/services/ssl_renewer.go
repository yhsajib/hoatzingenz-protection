package services

import (
	"log"
	"time"

	"hoatzingenz-protection/api/models"
)

func StartSSLAutoRenewer(v *VHostAutomationEngine, getSitesFunc func() []models.Website) {
	go func() {
		log.Println("[SSL AUTO-RENEW] Background Let's Encrypt Certificate Auto-Renewer active (12h interval)")
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			sites := getSitesFunc()
			for _, site := range sites {
				if !site.SSLEnabled {
					continue
				}
				certInfo, err := ReadCertInfo(site.DomainName)
				if err == nil && certInfo != nil {
					if certInfo.DaysLeft <= 30 {
						log.Printf("[SSL AUTO-RENEW] Certificate for %s expires in %d days. Triggering auto-renewal...", site.DomainName, certInfo.DaysLeft)
						out, err := v.RenewSSL(site.DomainName)
						if err != nil {
							log.Printf("[SSL AUTO-RENEW ERROR] Renewal failed for %s: %v", site.DomainName, err)
						} else {
							log.Printf("[SSL AUTO-RENEW SUCCESS] Successfully renewed SSL for %s: %s", site.DomainName, out)
						}
					}
				}
			}
		}
	}()
}
