package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hoatzingenz-protection/api/models"
)

type BackupInfo struct {
	ID            string    `json:"id"`
	DomainName    string    `json:"domain_name"`
	FileName      string    `json:"file_name"`
	FilePath      string    `json:"file_path"`
	SizeBytes     int64     `json:"size_bytes"`
	SizeFormatted string    `json:"size_formatted"`
	StorageType   string    `json:"storage_type"`
	CreatedAt     time.Time `json:"created_at"`
}

func BackupDir() string {
	dir := os.Getenv("HZ_BACKUP_DIR")
	if dir != "" {
		return dir
	}
	base := "/var/lib/hoatzingenz/backups"
	if err := os.MkdirAll(base, 0755); err != nil {
		localFallback := "./data/backups"
		_ = os.MkdirAll(localFallback, 0755)
		return localFallback
	}
	return base
}

func (v *VHostAutomationEngine) CreateFullBackup(site models.Website) (*BackupInfo, error) {
	outDir := BackupDir()
	_ = os.MkdirAll(outDir, 0755)

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("backup_%s_%s.tar.gz", site.DomainName, timestamp)
	targetPath := filepath.Join(outDir, filename)

	outFile, err := os.Create(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup file: %w", err)
	}

	gw := gzip.NewWriter(outFile)
	tw := tar.NewWriter(gw)

	docRoot := SiteRootDir(site.DomainName)
	if _, err := os.Stat(docRoot); os.IsNotExist(err) {
		localFallback := filepath.Join("./data/sites", site.DomainName)
		if _, err2 := os.Stat(localFallback); err2 == nil {
			docRoot = localFallback
		}
	}

	if _, err := os.Stat(docRoot); err == nil {
		_ = filepath.Walk(docRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			relPath, err := filepath.Rel(docRoot, path)
			if err != nil {
				return nil
			}
			tarHeader, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return nil
			}
			tarHeader.Name = filepath.ToSlash(filepath.Join("files", relPath))
			if err := tw.WriteHeader(tarHeader); err != nil {
				return nil
			}
			file, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()
			_, _ = io.Copy(tw, file)
			return nil
		})
	}

	if site.DBName != "" {
		sqlDump, dbErr := v.MySQLDump(site.DBName)
		if dbErr == nil && len(sqlDump) > 0 {
			hdr := &tar.Header{
				Name:    fmt.Sprintf("database_%s.sql", site.DBName),
				Mode:    0644,
				Size:    int64(len(sqlDump)),
				ModTime: time.Now(),
			}
			if err := tw.WriteHeader(hdr); err == nil {
				_, _ = tw.Write(sqlDump)
			}
		}
	}

	_ = tw.Close()
	_ = gw.Close()
	_ = outFile.Close()

	fi, _ := os.Stat(targetPath)
	size := int64(0)
	if fi != nil {
		size = fi.Size()
	}

	cfg := GetBackupConfig(site.DomainName)

	info := &BackupInfo{
		ID:            filename,
		DomainName:    site.DomainName,
		FileName:      filename,
		FilePath:      targetPath,
		SizeBytes:     size,
		SizeFormatted: formatBytes(size),
		StorageType:   cfg.StorageType,
		CreatedAt:     time.Now(),
	}

	if cfg.Enabled {
		if cfg.StorageType == "s3" && cfg.S3.Bucket != "" {
			go func() {
				if err := UploadToS3(targetPath, cfg.S3); err != nil {
					log.Printf("[BACKUP WARN] S3 cloud upload failed for %s: %v", site.DomainName, err)
				} else {
					log.Printf("[BACKUP SUCCESS] S3 cloud upload completed for %s", site.DomainName)
				}
			}()
		} else if cfg.StorageType == "sftp" && cfg.SFTP.Host != "" {
			go func() {
				if err := UploadToSFTP(targetPath, cfg.SFTP); err != nil {
					log.Printf("[BACKUP WARN] SFTP cloud upload failed for %s: %v", site.DomainName, err)
				} else {
					log.Printf("[BACKUP SUCCESS] SFTP cloud upload completed for %s", site.DomainName)
				}
			}()
		}
		if cfg.RetentionCount > 0 {
			EnforceRetentionPolicy(site.DomainName, cfg.RetentionCount)
		}
	}

	log.Printf("[BACKUP] Created backup for domain %s at %s (%s)", site.DomainName, targetPath, info.SizeFormatted)
	return info, nil
}

func ListSiteBackups(domain string) []BackupInfo {
	outDir := BackupDir()
	files, err := os.ReadDir(outDir)
	if err != nil {
		return []BackupInfo{}
	}

	cfg := GetBackupConfig(domain)

	var list []BackupInfo
	prefix := "backup_" + domain + "_"
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".tar.gz") {
			continue
		}
		if domain != "" && !strings.HasPrefix(f.Name(), prefix) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			continue
		}

		parts := strings.Split(f.Name(), "_")
		siteDomain := domain
		if len(parts) >= 3 {
			siteDomain = parts[1]
		}

		list = append(list, BackupInfo{
			ID:            f.Name(),
			DomainName:    siteDomain,
			FileName:      f.Name(),
			FilePath:      filepath.Join(outDir, f.Name()),
			SizeBytes:     info.Size(),
			SizeFormatted: formatBytes(info.Size()),
			StorageType:   cfg.StorageType,
			CreatedAt:     info.ModTime(),
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})

	return list
}

func DeleteBackupFile(filename string) error {
	outDir := BackupDir()
	cleanName := filepath.Base(filename)
	path := filepath.Join(outDir, cleanName)
	return os.Remove(path)
}

func EnforceRetentionPolicy(domain string, maxRetention int) {
	if maxRetention <= 0 {
		return
	}
	backups := ListSiteBackups(domain)
	if len(backups) > maxRetention {
		for _, b := range backups[maxRetention:] {
			_ = DeleteBackupFile(b.FileName)
			log.Printf("[BACKUP RETENTION] Pruned old backup archive: %s", b.FileName)
		}
	}
}

func GetBackupConfig(domain string) models.BackupConfig {
	cfgDir := filepath.Join(BackupDir(), "configs")
	_ = os.MkdirAll(cfgDir, 0755)
	file := filepath.Join(cfgDir, domain+".json")

	var cfg models.BackupConfig
	data, err := os.ReadFile(file)
	if err == nil {
		_ = json.Unmarshal(data, &cfg)
	}

	if cfg.DomainName == "" {
		cfg = models.BackupConfig{
			DomainName:     domain,
			Enabled:        false,
			Schedule:       "daily",
			RetentionCount: 7,
			StorageType:    "local",
			UpdatedAt:      time.Now(),
		}
	}
	return cfg
}

func SaveBackupConfig(cfg models.BackupConfig) error {
	cfgDir := filepath.Join(BackupDir(), "configs")
	_ = os.MkdirAll(cfgDir, 0755)
	file := filepath.Join(cfgDir, cfg.DomainName+".json")
	cfg.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}

func UploadToS3(filePath string, s3 models.S3Config) error {
	if s3.Bucket == "" || s3.AccessKey == "" || s3.SecretKey == "" {
		return fmt.Errorf("S3 bucket, access key, and secret key required")
	}
	filename := filepath.Base(filePath)
	objectKey := filename
	if s3.PathPrefix != "" {
		objectKey = strings.Trim(s3.PathPrefix, "/") + "/" + filename
	}

	endpoint := s3.Endpoint
	if endpoint == "" {
		region := s3.Region
		if region == "" {
			region = "us-east-1"
		}
		endpoint = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", s3.Bucket, region)
	} else {
		if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
			endpoint = "https://" + endpoint
		}
		endpoint = fmt.Sprintf("%s/%s", strings.TrimSuffix(endpoint, "/"), s3.Bucket)
	}

	reqURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(endpoint, "/"), objectKey)

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, reqURL, bytes.NewReader(fileData))
	if err != nil {
		return fmt.Errorf("failed to create S3 request: %w", err)
	}

	now := time.Now().UTC()
	dateStr := now.Format("20060102T150405Z")
	dayStr := now.Format("20060102")

	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("x-amz-date", dateStr)

	region := s3.Region
	if region == "" {
		region = "us-east-1"
	}

	hasher := sha256.New()
	hasher.Write(fileData)
	payloadHash := hex.EncodeToString(hasher.Sum(nil))
	req.Header.Set("x-amz-content-sha256", payloadHash)

	canonicalHeaders := fmt.Sprintf("content-type:application/gzip\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", req.URL.Host, payloadHash, dateStr)
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalReq := fmt.Sprintf("PUT\n/%s\n\n%s\n%s\n%s", objectKey, canonicalHeaders, signedHeaders, payloadHash)

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dayStr, region)
	reqHash := sha256.Sum256([]byte(canonicalReq))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", dateStr, scope, hex.EncodeToString(reqHash[:]))

	kDate := hmacSHA256([]byte("AWS4"+s3.SecretKey), []byte(dayStr))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s3.AccessKey, scope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 upload request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("S3 upload failed with status %s: %s", resp.Status, string(body))
	}

	return nil
}

func UploadToSFTP(filePath string, sftp models.SFTPConfig) error {
	if sftp.Host == "" || sftp.Username == "" {
		return fmt.Errorf("SFTP host and username required")
	}
	port := sftp.Port
	if port <= 0 {
		port = 22
	}
	remoteDir := sftp.RemoteDir
	if remoteDir == "" {
		remoteDir = "/backups"
	}

	filename := filepath.Base(filePath)
	remotePath := filepath.Join(remoteDir, filename)

	if sshPath, err := exec.LookPath("sshpass"); err == nil && sftp.Password != "" {
		cmd := exec.Command(sshPath, "-p", sftp.Password, "scp", "-P", fmt.Sprintf("%d", port), "-o", "StrictHostKeyChecking=no", filePath, fmt.Sprintf("%s@%s:%s", sftp.Username, sftp.Host, remotePath))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("SFTP transfer error: %s (%v)", string(out), err)
		}
		return nil
	}

	cmd := exec.Command("scp", "-P", fmt.Sprintf("%d", port), "-o", "StrictHostKeyChecking=no", filePath, fmt.Sprintf("%s@%s:%s", sftp.Username, sftp.Host, remotePath))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SFTP transfer error: %s (%v)", string(out), err)
	}
	return nil
}

func TestStorageConnection(cfg models.BackupConfig) error {
	if cfg.StorageType == "s3" {
		if cfg.S3.Bucket == "" || cfg.S3.AccessKey == "" || cfg.S3.SecretKey == "" {
			return fmt.Errorf("Bucket name, access key, and secret key are required for S3")
		}
		return nil
	}
	if cfg.StorageType == "sftp" {
		if cfg.SFTP.Host == "" || cfg.SFTP.Username == "" {
			return fmt.Errorf("SFTP host and username are required")
		}
		return nil
	}
	return nil
}

func hmacSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
