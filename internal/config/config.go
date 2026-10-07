// Package config memuat dan menyimpan konfigurasi Perisai WAF dari file YAML.
// Merupakan port dari perisai/config.py (Python).
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Host             string   `yaml:"host"`
	Port             int      `yaml:"port"`
	UpstreamHost     string   `yaml:"upstream_host"`
	UpstreamPort     int      `yaml:"upstream_port"`
	UpstreamTLS      bool     `yaml:"upstream_tls"`
	MaxBodyMB        int      `yaml:"max_body_mb"`
	RequestTimeout   int      `yaml:"request_timeout"`
	UpstreamTLSVerify bool    `yaml:"upstream_tls_verify"`
	TrustedProxies   []string `yaml:"trusted_proxies"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

type Thresholds struct {
	AgentScore float64 `yaml:"agent_score"`
	BlockScore float64 `yaml:"block_score"`
}

type LLMConfig struct {
	BaseURL string `yaml:"base_url"`
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	Timeout int    `yaml:"timeout"`
}

type SystemOneConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	Model    string `yaml:"model"`
	Timeout  int    `yaml:"timeout"`
}

type AgentConfig struct {
	Backend       string         `yaml:"backend"` // auto | heuristic | llm | systemone
	MinConfidence float64        `yaml:"min_confidence"`
	LLM           LLMConfig      `yaml:"llm"`
	SystemOne     SystemOneConfig `yaml:"systemone"`
}

type RateLimitConfig struct {
	Enabled bool    `yaml:"enabled"`
	RPS     float64 `yaml:"rps"`
	Burst   int     `yaml:"burst"`
}

type ReputationConfig struct {
	Enabled        bool `yaml:"enabled"`
	StrikesToBlock int  `yaml:"strikes_to_block"`
	WindowSeconds  int  `yaml:"window_seconds"`
	BlockSeconds   int  `yaml:"block_seconds"`
}

type LearningConfig struct {
	Enabled       bool    `yaml:"enabled"`
	AutoApprove   bool    `yaml:"auto_approve"`
	MinConfidence float64 `yaml:"min_confidence"`
}

type CloudflareConfig struct {
	APIToken string `yaml:"api_token"`
}

type RecaptchaConfig struct {
	Enabled   bool   `yaml:"enabled"`
	SiteKey   string `yaml:"site_key"`
	SecretKey string `yaml:"secret_key"`
	Mode      string `yaml:"mode"` // v2 | v3
}

type DashboardConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Token        string `yaml:"token"`
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

type GeoConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"` // auto | mmdb | api | off
	MMDBPath string `yaml:"mmdb_path"`
}

// TerminalConfig mengatur menu Terminal di dashboard: shell interaktif
// via websocket yang berjalan di folder kerja aplikasi (di Docker: /app).
type TerminalConfig struct {
	Enabled bool   `yaml:"enabled"`
	Shell   string `yaml:"shell"`    // default "bash", fallback "sh" bila tak ada
	WorkDir string `yaml:"work_dir"` // default "" = direktori kerja proses saat start
}

type UploadScanConfig struct {
	Enabled           bool     `yaml:"enabled"`
	MaxFileMB         int      `yaml:"max_file_mb"`
	BlockedExtensions []string `yaml:"blocked_extensions"`
}

// Site adalah satu website yang dilindungi (multi-site).
type Site struct {
	ID                 string   `yaml:"id"`
	Domain             string   `yaml:"domain"`
	UpstreamHost       string   `yaml:"upstream_host"`
	UpstreamPort       int      `yaml:"upstream_port"`
	UpstreamTLS        bool     `yaml:"upstream_tls"`
	UpstreamTLSVerify  bool     `yaml:"upstream_tls_verify"`
	PreserveHost       bool     `yaml:"preserve_host"`
	Enabled            bool     `yaml:"enabled"`
	AgentEnabled       bool     `yaml:"agent_enabled"`
	DisabledRules      []string `yaml:"disabled_rules"`
	TLSCert            string   `yaml:"tlscert"`
	TLSKey             string   `yaml:"tlskey"`
	TLSExpiresAt       float64  `yaml:"tls_expires_at"`
	DDoSMode           bool     `yaml:"ddos_mode"`
	DDoSRPS            float64  `yaml:"ddos_rps"`
	CacheEnabled       bool     `yaml:"cache_enabled"`
	CacheTTL           int      `yaml:"cache_ttl"`
	CacheMaxEntries    int      `yaml:"cache_max_entries"`
	CacheMaxObjectKB   int      `yaml:"cache_max_object_kb"`
	CacheBypassCookies []string `yaml:"cache_bypass_cookies"`
	RecaptchaEnabled   bool     `yaml:"recaptcha_enabled"`
	CFZoneID           string   `yaml:"cf_zone_id"`
}

type WAFConfig struct {
	Server     ServerConfig     `yaml:"server"`
	TLS        TLSConfig        `yaml:"tls"`
	Thresholds Thresholds       `yaml:"thresholds"`
	Agent      AgentConfig      `yaml:"agent"`
	RateLimit  RateLimitConfig  `yaml:"ratelimit"`
	Reputation ReputationConfig `yaml:"reputation"`
	Learning   LearningConfig   `yaml:"learning"`
	Dashboard  DashboardConfig  `yaml:"dashboard"`
	Recaptcha  RecaptchaConfig  `yaml:"recaptcha"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
	DataDir    string           `yaml:"data_dir"`
	Geo        GeoConfig        `yaml:"geo"`
	Uploads    UploadScanConfig `yaml:"uploads"`
	Terminal   TerminalConfig   `yaml:"terminal"`

	ConfigPath string `yaml:"-"`
}

func defaultConfig() *WAFConfig {
	return &WAFConfig{
		Server: ServerConfig{
			Host: "0.0.0.0", Port: 8080,
			UpstreamHost: "127.0.0.1", UpstreamPort: 8000,
			MaxBodyMB: 10, RequestTimeout: 15, UpstreamTLSVerify: true,
		},
		Thresholds: Thresholds{AgentScore: 25, BlockScore: 60},
		Agent: AgentConfig{
			Backend: "auto", MinConfidence: 0.55,
			LLM:       LLMConfig{BaseURL: "http://127.0.0.1:11434/v1", Model: "llama3.1", Timeout: 20},
			SystemOne: SystemOneConfig{Enabled: true, Endpoint: "https://ai.skyzo.biz.id/v1/systemone", Model: "oc/jev-1.13-free", Timeout: 10},
		},
		RateLimit:  RateLimitConfig{Enabled: true, RPS: 20, Burst: 40},
		Reputation: ReputationConfig{Enabled: true, StrikesToBlock: 5, WindowSeconds: 600, BlockSeconds: 3600},
		Learning:   LearningConfig{Enabled: true, MinConfidence: 0.85},
		Dashboard:  DashboardConfig{Enabled: true, Host: "127.0.0.1", Port: 8899, Token: "ubah-token-ini", Username: "admin"},
		Geo:        GeoConfig{Enabled: true, Provider: "auto"},
		Terminal:   TerminalConfig{Enabled: true, Shell: "bash"},
		Uploads: UploadScanConfig{Enabled: true, MaxFileMB: 10, BlockedExtensions: []string{
			"php", "phtml", "phar", "asp", "aspx", "jsp", "exe", "dll",
			"sh", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs",
		}},
		DataDir: "./data",
	}
}

// LoadConfig membaca file YAML (bila ada) di atas nilai default.
func LoadConfig(path string) (*WAFConfig, error) {
	cfg := defaultConfig()
	if data, err := os.ReadFile(path); err == nil {
		// Unmarshal di atas default agar key yang tak ada tetap default.
		// yaml.Unmarshal menimpa struct apa adanya; karena kita mulai dari
		// default, field yang tak disebut di file tetap bernilai default
		// kecuali tipenya struct bersarang yang di-unmarshal parsial —
		// itu pun aman karena zero value hanya menimpa bila key ada.
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}
	if cfg.Agent.LLM.APIKey == "" {
		cfg.Agent.LLM.APIKey = os.Getenv("PERISAI_LLM_KEY")
	}
	if cfg.Agent.SystemOne.APIKey == "" {
		cfg.Agent.SystemOne.APIKey = os.Getenv("PERISAI_SYSTEMONE_KEY")
	}
	if cfg.Recaptcha.SecretKey == "" {
		cfg.Recaptcha.SecretKey = os.Getenv("PERISAI_RECAPTCHA_SECRET")
	}
	if cfg.Cloudflare.APIToken == "" {
		cfg.Cloudflare.APIToken = os.Getenv("PERISAI_CF_TOKEN")
	}
	if v := os.Getenv("PERISAI_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	cfg.ConfigPath = path
	return cfg, nil
}

func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadRawMap(path string) (map[string]any, error) {
	m := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func nestedMap(m map[string]any, key string) map[string]any {
	sub, _ := m[key].(map[string]any)
	if sub == nil {
		sub = map[string]any{}
		m[key] = sub
	}
	return sub
}

// SaveLLMConfig menyimpan section agent.llm. apiKey nil = jangan ubah.
func SaveLLMConfig(path, backend string, minConf float64, baseURL, model string, timeout int, apiKey *string) error {
	m, err := loadRawMap(path)
	if err != nil {
		return err
	}
	agent := nestedMap(m, "agent")
	llm := nestedMap(agent, "llm")
	agent["backend"] = backend
	agent["min_confidence"] = minConf
	llm["base_url"] = baseURL
	if apiKey != nil {
		llm["api_key"] = *apiKey
	}
	llm["model"] = model
	llm["timeout"] = timeout
	return writeYAML(path, m)
}

// SaveSystemOneConfig menyimpan section agent.systemone. apiKey nil = jangan ubah.
func SaveSystemOneConfig(path string, enabled bool, endpoint, model string, timeout int, apiKey *string) error {
	m, err := loadRawMap(path)
	if err != nil {
		return err
	}
	agent := nestedMap(m, "agent")
	s1 := nestedMap(agent, "systemone")
	s1["enabled"] = enabled
	s1["endpoint"] = endpoint
	if apiKey != nil {
		s1["api_key"] = *apiKey
	}
	s1["model"] = model
	s1["timeout"] = timeout
	return writeYAML(path, m)
}

// SaveCFConfig menyimpan token Cloudflare. apiToken nil = jangan ubah.
func SaveCFConfig(path string, apiToken *string) error {
	m, err := loadRawMap(path)
	if err != nil {
		return err
	}
	cf := nestedMap(m, "cloudflare")
	if apiToken != nil {
		cf["api_token"] = *apiToken
	}
	return writeYAML(path, m)
}

// SaveRecaptchaConfig menyimpan section recaptcha. secretKey nil = jangan ubah.
func SaveRecaptchaConfig(path string, enabled bool, siteKey string, secretKey *string, mode string) error {
	m, err := loadRawMap(path)
	if err != nil {
		return err
	}
	rc := nestedMap(m, "recaptcha")
	rc["enabled"] = enabled
	rc["site_key"] = siteKey
	if secretKey != nil {
		rc["secret_key"] = *secretKey
	}
	if mode != "v2" && mode != "v3" {
		mode = "v2"
	}
	rc["mode"] = mode
	return writeYAML(path, m)
}

// SaveDashboardAuth menyimpan username + hash password dashboard.
func SaveDashboardAuth(path, username, passwordHash string) error {
	m, err := loadRawMap(path)
	if err != nil {
		return err
	}
	dash := nestedMap(m, "dashboard")
	dash["username"] = username
	dash["password_hash"] = passwordHash
	return writeYAML(path, m)
}

// AbsPath mengembalikan path absolut relatif terhadap file config.
func (c *WAFConfig) AbsPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(c.ConfigPath), p)
}
