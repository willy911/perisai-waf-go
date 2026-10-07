package config

import (
	"os"
	"path/filepath"
	"testing"
)

func setEnvs(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestApplyEnvPorts(t *testing.T) {
	setEnvs(t, map[string]string{
		"PORT": "18080", "DASHBOARD_PORT": "18899", "HOSTNAME": "127.0.0.1",
		"DATA_DIR": filepath.Join(t.TempDir(), "data"),
	})
	cfg := defaultConfig()
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if cfg.Server.Port != 18080 || cfg.Dashboard.Port != 18899 {
		t.Fatalf("port tidak override: %+v", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" || cfg.Dashboard.Host != "127.0.0.1" {
		t.Fatalf("hostname tidak override")
	}
	if _, err := os.Stat(cfg.DataDir); err != nil {
		t.Fatalf("DATA_DIR tidak dibuat: %v", err)
	}
}

func TestApplyEnvInitialPassword(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	setEnvs(t, map[string]string{
		"INITIAL_USER": "owner", "INITIAL_PASSWORD": "rahasia-kuat-123",
	})
	cfg := defaultConfig()
	cfg.ConfigPath = cfgPath
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if cfg.Dashboard.Username != "owner" || cfg.Dashboard.PasswordHash == "" {
		t.Fatalf("password awal tidak diset: %+v", cfg.Dashboard)
	}
	// Harus tersimpan ke file config.
	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.Dashboard.Username != "owner" || loaded.Dashboard.PasswordHash == "" {
		t.Fatalf("password awal tidak persist: %+v", loaded.Dashboard)
	}
	// Password yang sudah ada tidak boleh ditimpa env.
	setEnvs(t, map[string]string{"INITIAL_PASSWORD": "jangan-timpa"})
	if err := ApplyEnv(loaded); err != nil {
		t.Fatalf("ApplyEnv kedua: %v", err)
	}
	if loaded.Dashboard.PasswordHash != cfg.Dashboard.PasswordHash {
		t.Fatal("password yang sudah ada tertimpa env!")
	}
}

func TestApplyEnvInvalidPort(t *testing.T) {
	setEnvs(t, map[string]string{"PORT": "bukan-angka"})
	cfg := defaultConfig()
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("port invalid harus fallback ke default, dapat %d", cfg.Server.Port)
	}
}
