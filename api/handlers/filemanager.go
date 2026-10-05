package handlers

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hoatzingenz-protection/api/models"
)

const (
	maxEditableSize = 5 << 20   // 5 MB
	maxUploadSize   = 256 << 20 // 256 MB
)

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$`)

// webRootBase returns the directory under which each site lives (<base>/<domain>).
func webRootBase() string {
	if v := os.Getenv("HZ_WEB_ROOT"); v != "" {
		return v
	}
	return "/var/www/html"
}

func siteRoot(domain string) (string, error) {
	if domain == "" || strings.Contains(domain, "..") || !domainRe.MatchString(domain) {
		return "", fmt.Errorf("invalid domain")
	}
	return filepath.Join(webRootBase(), domain), nil
}

// resolvePath maps a user supplied path (absolute panel path or relative) to a real
// path guaranteed to be inside the site root (symlink escapes are rejected).
func resolvePath(root, userPath string) (string, error) {
	p := filepath.ToSlash(userPath)
	rootSlash := filepath.ToSlash(root)
	p = strings.TrimPrefix(p, rootSlash)
	p = strings.TrimPrefix(p, "/var/www/html/"+filepath.Base(root))
	full := filepath.Join(root, filepath.FromSlash(filepath.Clean("/"+p)))

	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	// Evaluate the deepest existing ancestor to detect symlink escapes.
	check := full
	for {
		if _, err := os.Lstat(check); err == nil {
			break
		}
		parent := filepath.Dir(check)
		if parent == check {
			break
		}
		check = parent
	}
	real, err := filepath.EvalSymlinks(check)
	if err != nil {
		return "", err
	}
	if real != rootReal && !strings.HasPrefix(real, rootReal+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes site root")
	}
	return full, nil
}

func toItem(root, full string, info os.FileInfo) models.FileItem {
	ext := "folder"
	if !info.IsDir() {
		ext = strings.TrimPrefix(strings.ToLower(filepath.Ext(info.Name())), ".")
		if ext == "" {
			ext = strings.TrimPrefix(info.Name(), ".")
		}
	}
	return models.FileItem{
		Name:        info.Name(),
		Path:        filepath.ToSlash(full),
		IsDir:       info.IsDir(),
		Size:        info.Size(),
		Permissions: fmt.Sprintf("%04o", info.Mode().Perm()),
		Extension:   ext,
		UpdatedAt:   info.ModTime(),
	}
}

func fmError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// HandleWebsiteFiles is a real file manager rooted at <web root>/<domain>.
//
//	GET    ?domain&path            list directory / read file
//	GET    ?domain&path&download=1 download file
//	POST   json {domain,path,content}                      save file
//	POST   json {domain,path,action: mkdir|create|rename|delete|chmod|install_wordpress, ...}
//	POST   multipart (domain, path=<dir>, files[])         upload
//	DELETE ?domain&path
func (h *APIHandler) HandleWebsiteFiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	var jsonReq struct {
		Domain      string `json:"domain"`
		Path        string `json:"path"`
		Content     string `json:"content"`
		Action      string `json:"action"`
		NewName     string `json:"new_name"`
		Permissions string `json:"permissions"`
	}
	isMultipart := strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data")

	if r.Method == http.MethodPost {
		if isMultipart {
			r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				fmError(w, http.StatusBadRequest, "Invalid upload: "+err.Error())
				return
			}
			domain = r.FormValue("domain")
			jsonReq.Path = r.FormValue("path")
		} else {
			if err := json.NewDecoder(r.Body).Decode(&jsonReq); err != nil {
				fmError(w, http.StatusBadRequest, "Invalid request")
				return
			}
			domain = jsonReq.Domain
		}
	}

	root, err := siteRoot(domain)
	if err != nil {
		fmError(w, http.StatusBadRequest, err.Error())
		return
	}

	userPath := q.Get("path")
	if r.Method == http.MethodPost {
		userPath = jsonReq.Path
	}

	// Allow initial listing of a non-provisioned site by creating its directory on demand.
	if r.Method == http.MethodGet && userPath == "" {
		if _, statErr := os.Stat(root); os.IsNotExist(statErr) {
			if mkErr := os.MkdirAll(root, 0755); mkErr != nil {
				fmError(w, http.StatusNotFound, "Site directory does not exist and could not be created: "+mkErr.Error())
				return
			}
		}
	}
	if _, statErr := os.Stat(root); statErr != nil {
		fmError(w, http.StatusNotFound, "Site directory not found: "+root)
		return
	}

	full, err := resolvePath(root, userPath)
	if err != nil {
		fmError(w, http.StatusForbidden, "Access denied: "+err.Error())
		return
	}

	switch r.Method {
	case http.MethodGet:
		info, err := os.Stat(full)
		if err != nil {
			fmError(w, http.StatusNotFound, "Not found")
			return
		}
		if info.IsDir() {
			entries, err := os.ReadDir(full)
			if err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			items := make([]models.FileItem, 0, len(entries))
			for _, e := range entries {
				fi, err := e.Info()
				if err != nil {
					continue
				}
				if fi.Mode()&os.ModeSymlink != 0 {
					if st, err := os.Stat(filepath.Join(full, e.Name())); err == nil {
						fi = st
					}
				}
				items = append(items, toItem(root, filepath.Join(full, e.Name()), fi))
			}
			sort.Slice(items, func(i, j int) bool {
				if items[i].IsDir != items[j].IsDir {
					return items[i].IsDir
				}
				return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
			})
			isWP := false
			if _, err := os.Stat(filepath.Join(root, "wp-includes")); err == nil {
				isWP = true
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data":         items,
				"path":         filepath.ToSlash(full),
				"root":         filepath.ToSlash(root),
				"wordpress":    isWP,
				"is_root":      full == root,
				"parent":       parentPath(root, full),
			})
			return
		}
		if q.Get("download") == "1" {
			w.Header().Set("Content-Disposition", "attachment; filename=\""+info.Name()+"\"")
			http.ServeFile(w, r, full)
			return
		}
		if info.Size() > maxEditableSize {
			fmError(w, http.StatusRequestEntityTooLarge, "File too large to edit in browser (use download)")
			return
		}
		data, err := os.ReadFile(full)
		if err != nil {
			fmError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"path":    filepath.ToSlash(full),
			"content": string(data),
			"size":    info.Size(),
		})

	case http.MethodPost:
		if isMultipart {
			dir := full
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			count := 0
			for _, fhs := range r.MultipartForm.File {
				for _, fh := range fhs {
					name := filepath.Base(fh.Filename)
					if name == "." || name == "/" || name == "" {
						continue
					}
					src, err := fh.Open()
					if err != nil {
						continue
					}
					dst, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
					if err != nil {
						src.Close()
						fmError(w, http.StatusInternalServerError, err.Error())
						return
					}
					_, cpErr := io.Copy(dst, src)
					dst.Close()
					src.Close()
					if cpErr != nil {
						fmError(w, http.StatusInternalServerError, cpErr.Error())
						return
					}
					count++
				}
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"message": fmt.Sprintf("Uploaded %d file(s)", count)})
			return
		}

		switch jsonReq.Action {
		case "", "save":
			if userPath == "" {
				fmError(w, http.StatusBadRequest, "path required")
				return
			}
			if fi, err := os.Stat(full); err == nil && fi.IsDir() {
				fmError(w, http.StatusBadRequest, "Path is a directory")
				return
			}
			mode := os.FileMode(0644)
			if fi, err := os.Stat(full); err == nil {
				mode = fi.Mode().Perm()
			}
			if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := os.WriteFile(full, []byte(jsonReq.Content), mode); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": "File saved successfully"})

		case "create":
			if _, err := os.Stat(full); err == nil {
				fmError(w, http.StatusConflict, "Already exists")
				return
			}
			if err := os.WriteFile(full, []byte(jsonReq.Content), 0644); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]string{"message": "File created"})

		case "mkdir":
			if err := os.MkdirAll(full, 0755); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]string{"message": "Folder created"})

		case "rename":
			if jsonReq.NewName == "" || strings.ContainsAny(jsonReq.NewName, `/\`) || jsonReq.NewName == ".." {
				fmError(w, http.StatusBadRequest, "Invalid new name")
				return
			}
			if full == root {
				fmError(w, http.StatusForbidden, "Cannot rename site root")
				return
			}
			dest := filepath.Join(filepath.Dir(full), jsonReq.NewName)
			if _, err := os.Stat(dest); err == nil {
				fmError(w, http.StatusConflict, "Target already exists")
				return
			}
			if err := os.Rename(full, dest); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": "Renamed"})

		case "delete":
			if full == root {
				fmError(w, http.StatusForbidden, "Cannot delete site root")
				return
			}
			if err := os.RemoveAll(full); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": "Deleted"})

		case "chmod":
			m, err := strconv.ParseUint(jsonReq.Permissions, 8, 32)
			if err != nil || m > 0777 {
				fmError(w, http.StatusBadRequest, "Invalid permissions (use octal e.g. 0755)")
				return
			}
			if err := os.Chmod(full, os.FileMode(m)); err != nil {
				fmError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": "Permissions updated"})

		case "install_wordpress":
			if err := installWordPress(root); err != nil {
				fmError(w, http.StatusInternalServerError, "WordPress install failed: "+err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": "WordPress core installed"})

		default:
			fmError(w, http.StatusBadRequest, "Unknown action")
		}

	case http.MethodDelete:
		if userPath == "" || full == root {
			fmError(w, http.StatusForbidden, "Cannot delete site root")
			return
		}
		if err := os.RemoveAll(full); err != nil {
			fmError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "Deleted"})

	default:
		fmError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func parentPath(root, full string) string {
	if full == root {
		return filepath.ToSlash(root)
	}
	return filepath.ToSlash(filepath.Dir(full))
}

// installWordPress downloads the latest WordPress release and extracts it into root,
// without overwriting existing files (wp-config.php, wp-content customisations are kept).
func installWordPress(root string) error {
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
