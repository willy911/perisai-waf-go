// Dukungan konfigurasi via environment variable — dipakai terutama untuk
// instalasi Docker / Docker Compose ala 9router (tanpa file config pun jalan).
//
// Variabel yang didukung:
//
//	PORT / PERISAI_PORT               port proxy WAF (default 8080)
//	HOSTNAME                          host bind proxy+dashboard (default 0.0.0.0)
//	DASHBOARD_PORT / PERISAI_DASHBOARD_PORT
//	                                  port dashboard (default 8899)
//	DATA_DIR / PERISAI_DATA_DIR       direktori data SQLite (default ./data)
//	INITIAL_USER / PERISAI_ADMIN_USER username dashboard awal (default admin)
//	INITIAL_PASSWORD / PERISAI_ADMIN_PASSWORD
//	                                  password dashboard awal; hanya dipakai bila
//	                                  password_hash masih kosong — di-hash lalu
//	                                  disimpan ke config.yaml agar permanen
//	DASHBOARD_TOKEN / PERISAI_DASHBOARD_TOKEN
//	                                  token API statis dashboard
package config

import (
	"log"
	"os"
	"strconv"

	"github.com/willy911/perisai-waf/internal/auth"
)

// envFirst mengembalikan nilai env pertama yang tidak kosong.
func envFirst(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// ApplyEnv menerapkan override environment variable ke cfg. Dipanggil sekali
// saat startup (cmd/perisai) setelah LoadConfig. Mengembalikan error hanya
// bila gagal menyimpan password awal ke file config.
func ApplyEnv(cfg *WAFConfig) error {
	if v := envFirst("PORT", "PERISAI_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			cfg.Server.Port = p
		} else {
			log.Printf("peringatan: PORT=%q tidak valid, pakai %d", v, cfg.Server.Port)
		}
	}
	if v := envFirst("DASHBOARD_PORT", "PERISAI_DASHBOARD_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			cfg.Dashboard.Port = p
		} else {
			log.Printf("peringatan: DASHBOARD_PORT=%q tidak valid, pakai %d", v, cfg.Dashboard.Port)
		}
	}
	if v := os.Getenv("HOSTNAME"); v != "" {
		cfg.Server.Host = v
		cfg.Dashboard.Host = v
	}
	if v := envFirst("DATA_DIR", "PERISAI_DATA_DIR"); v != "" {
		cfg.DataDir = v
		if err := os.MkdirAll(v, 0o755); err != nil {
			log.Printf("peringatan: gagal membuat DATA_DIR %q: %v", v, err)
		}
	}
	if v := envFirst("DASHBOARD_TOKEN", "PERISAI_DASHBOARD_TOKEN"); v != "" {
		cfg.Dashboard.Token = v
	}

	// Password awal ala 9router (INITIAL_PASSWORD): hanya bila belum ada
	// password tersimpan, agar tidak menimpa password yang sudah diatur.
	if pw := envFirst("INITIAL_PASSWORD", "PERISAI_ADMIN_PASSWORD"); pw != "" && cfg.Dashboard.PasswordHash == "" {
		user := envFirst("INITIAL_USER", "PERISAI_ADMIN_USER")
		if user == "" {
			user = "admin"
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		cfg.Dashboard.Username = user
		cfg.Dashboard.PasswordHash = hash
		path := cfg.ConfigPath
		if path == "" {
			path = "config.yaml"
		}
		if err := SaveDashboardAuth(path, user, hash); err != nil {
			return err
		}
		log.Printf("[perisai] password awal dashboard diset untuk user %q (tersimpan di %s)", user, path)
	}
	return nil
}
