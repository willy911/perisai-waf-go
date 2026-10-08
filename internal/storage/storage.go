// Package storage menyediakan penyimpanan SQLite untuk Perisai WAF:
// log request, hasil agent, usulan aturan, reputasi IP, situs, daftar IP,
// grup IP, pengaturan, dan cache geo.
//
// Merupakan port dari perisai/storage.py (Python). DDL SQLite dipertahankan
// persis sama dengan Python agar database lama tetap bisa dibaca.
package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Storage membungkus koneksi SQLite. Semua method publik dikunci mutex
// agar aman dipakai dari banyak goroutine (proxy Go berjalan multi-goroutine).
type Storage struct {
	DB      *sql.DB
	mu      sync.Mutex
	dataDir string
}

// New membuka (atau membuat) dataDir/perisai.db lalu menjalankan migrasi DDL.
func New(dataDir string) (*Storage, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("gagal membuat data dir: %w", err)
	}
	path := filepath.Join(dataDir, "perisai.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // satu koneksi seperti Python (threading.Lock)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("gagal set WAL: %w", err)
	}
	s := &Storage{DB: db, dataDir: dataDir}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close menutup koneksi database.
func (s *Storage) Close() error {
	return s.DB.Close()
}

// DataDir mengembalikan direktori data (dipakai learner untuk
// custom_rules.json yang dikelola di luar SQLite).
func (s *Storage) DataDir() string {
	return s.dataDir
}

// -- migrasi DDL (persis seperti _migrate di Python) -----------------------

var baseSchema = []string{
	`CREATE TABLE IF NOT EXISTS requests (
		id TEXT PRIMARY KEY, ts REAL, ip TEXT, method TEXT,
		path TEXT, query TEXT, score REAL, decision TEXT,
		agent_conf REAL, duration_ms REAL, top_rule TEXT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)`,
	`CREATE TABLE IF NOT EXISTS agent_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, ts REAL,
		backend TEXT, decision TEXT, confidence REAL,
		reasoning TEXT, indicators TEXT, duration_ms REAL
	)`,
	`CREATE TABLE IF NOT EXISTS proposed_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, rule_json TEXT,
		status TEXT DEFAULT 'pending', source TEXT, note TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS ip_reputation (
		ip TEXT PRIMARY KEY, strikes INTEGER DEFAULT 0,
		window_start REAL, blocked_until REAL
	)`,
	`CREATE TABLE IF NOT EXISTS sites (
		id TEXT PRIMARY KEY, domain TEXT UNIQUE,
		upstream_host TEXT, upstream_port INTEGER,
		upstream_tls INTEGER DEFAULT 0,
		upstream_tls_verify INTEGER DEFAULT 1,
		preserve_host INTEGER DEFAULT 1,
		enabled INTEGER DEFAULT 1, agent_enabled INTEGER DEFAULT 1,
		disabled_rules TEXT DEFAULT '[]',
		tls_cert TEXT DEFAULT '', tls_key TEXT DEFAULT '',
		tls_expires_at REAL DEFAULT 0,
		created_at REAL
	)`,
	`CREATE TABLE IF NOT EXISTS ip_lists (
		id TEXT PRIMARY KEY, network TEXT,
		list TEXT, scope TEXT DEFAULT 'global',
		note TEXT DEFAULT '', expires_at REAL,
		created_at REAL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_iplists_list ON ip_lists(list)`,
	`CREATE TABLE IF NOT EXISTS geo_cache (
		ip TEXT PRIMARY KEY, country TEXT, city TEXT,
		lat REAL, lon REAL, ts REAL
	)`,
}

// kolom tambahan untuk database lama (urutan sama seperti _ensure_column Python)
var extraColumns = [][3]string{
	{"requests", "site_id", "TEXT DEFAULT ''"},
	{"agent_runs", "site_id", "TEXT DEFAULT ''"},
	{"sites", "upstream_tls", "INTEGER DEFAULT 0"},
	{"sites", "preserve_host", "INTEGER DEFAULT 1"},
	{"sites", "upstream_tls_verify", "INTEGER DEFAULT 1"},
	{"sites", "tls_expires_at", "REAL DEFAULT 0"},
	{"sites", "ddos_mode", "INTEGER DEFAULT 0"},
	{"sites", "ddos_rps", "REAL DEFAULT 5"},
	{"sites", "cache_enabled", "INTEGER DEFAULT 0"},
	{"sites", "cache_ttl", "INTEGER DEFAULT 60"},
	{"sites", "cache_max_entries", "INTEGER DEFAULT 1000"},
	{"sites", "cache_max_object_kb", "INTEGER DEFAULT 2048"},
	{"sites", "cache_bypass_cookies", "TEXT DEFAULT '[]'"},
	{"sites", "recaptcha_enabled", "INTEGER DEFAULT 0"},
	{"sites", "cf_zone_id", "TEXT DEFAULT ''"},
	{"sites", "blocked_countries", "TEXT DEFAULT '[]'"},
}

var lateTables = []string{
	`CREATE TABLE IF NOT EXISTS ip_groups (
		id TEXT PRIMARY KEY, name TEXT UNIQUE, kind TEXT DEFAULT 'black',
		description TEXT DEFAULT '', created_at REAL
	)`,
	`CREATE TABLE IF NOT EXISTS ip_group_members (
		group_id TEXT, cidr TEXT,
		PRIMARY KEY (group_id, cidr)
	)`,
	`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY, value TEXT
	)`,
}

func (s *Storage) migrate() error {
	for _, stmt := range baseSchema {
		if _, err := s.DB.Exec(stmt); err != nil {
			return fmt.Errorf("migrasi: %w", err)
		}
	}
	for _, c := range extraColumns {
		// abaikan bila kolom sudah ada (seperti OperationalError di Python)
		_, _ = s.DB.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c[0], c[1], c[2]))
	}
	for _, stmt := range lateTables {
		if _, err := s.DB.Exec(stmt); err != nil {
			return fmt.Errorf("migrasi: %w", err)
		}
	}
	return nil
}

// -- helper scan & konversi ----------------------------------------------

// scanRows mengubah *sql.Rows menjadi []map[string]any (kolom -> nilai).
// Nilai TEXT dikembalikan sebagai string (bukan []byte).
func scanRows(rows *sql.Rows) ([]map[string]any, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = normalizeValue(vals[i])
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// scanOneRow mengambil satu baris; mengembalikan sql.ErrNoRows bila kosong.
func scanOneRow(rows *sql.Rows) (map[string]any, error) {
	all, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, sql.ErrNoRows
	}
	return all[0], nil
}

func normalizeValue(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

// truncate memotong string ke n karakter (rune), seperti [:500] di Python.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// randomID menghasilkan id acak 12 karakter hex (seperti uuid4().hex[:12]).
func randomID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// -- helper konversi nilai map (site/ip entry memakai map[string]any) -----

func toString(v any, def string) string {
	switch t := v.(type) {
	case nil:
		return def
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func toBool(v any, def bool) bool {
	switch t := v.(type) {
	case nil:
		return def
	case bool:
		return t
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off", "":
			return false
		}
		return true
	default:
		return def
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func toInt(v any, def int) int {
	switch t := v.(type) {
	case nil:
		return def
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case bool:
		return boolInt(t)
	default:
		return def
	}
}

func toFloat(v any, def float64) float64 {
	switch t := v.(type) {
	case nil:
		return def
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return def
	}
}

// jsonListText mengubah nilai (string JSON / slice) menjadi teks JSON array.
func jsonListText(v any, def string) string {
	if v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		if strings.TrimSpace(s) == "" {
			return def
		}
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return def
	}
	return string(b)
}

// -- request log ----------------------------------------------------------

func (s *Storage) LogRequest(reqID string, ts float64, ip, method, path, query string,
	score float64, decision string, agentConf float64, durationMs float64,
	topRule, siteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec(
		`INSERT INTO requests
		 (id, ts, ip, method, path, query, score, decision,
		  agent_conf, duration_ms, top_rule, site_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		reqID, ts, ip, method, truncate(path, 500), truncate(query, 500),
		score, decision, agentConf, durationMs, topRule, siteID)
	return err
}

func (s *Storage) RecentRequests(limit int, siteID string) ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows *sql.Rows
	var err error
	if siteID != "" {
		rows, err = s.DB.Query(
			"SELECT * FROM requests WHERE site_id = ? ORDER BY ts DESC LIMIT ?",
			siteID, limit)
	} else {
		rows, err = s.DB.Query(
			"SELECT * FROM requests ORDER BY ts DESC LIMIT ?", limit)
	}
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

// Stats mengembalikan statistik request sejak sinceTS:
// {"total", "by_decision", "top_rules", "top_offenders"} seperti Python.
func (s *Storage) Stats(sinceTS float64) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.DB.Query(
		"SELECT decision, COUNT(*) c FROM requests WHERE ts >= ? GROUP BY decision",
		sinceTS)
	if err != nil {
		return nil, err
	}
	decRows, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	rows, err = s.DB.Query(
		`SELECT top_rule, COUNT(*) c FROM requests
		 WHERE ts >= ? AND top_rule != '' GROUP BY top_rule
		 ORDER BY c DESC LIMIT 5`, sinceTS)
	if err != nil {
		return nil, err
	}
	ruleRows, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	rows, err = s.DB.Query(
		`SELECT ip, COUNT(*) c FROM requests
		 WHERE ts >= ? AND decision IN ('block','challenge')
		 GROUP BY ip ORDER BY c DESC LIMIT 5`, sinceTS)
	if err != nil {
		return nil, err
	}
	ipRows, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	var total int64
	if err := s.DB.QueryRow(
		"SELECT COUNT(*) c FROM requests WHERE ts >= ?", sinceTS).Scan(&total); err != nil {
		return nil, err
	}

	byDecision := map[string]any{}
	for _, r := range decRows {
		byDecision[toString(r["decision"], "")] = r["c"]
	}
	topRules := []map[string]any{}
	for _, r := range ruleRows {
		topRules = append(topRules, map[string]any{"rule": r["top_rule"], "count": r["c"]})
	}
	topOffenders := []map[string]any{}
	for _, r := range ipRows {
		topOffenders = append(topOffenders, map[string]any{"ip": r["ip"], "count": r["c"]})
	}
	return map[string]any{
		"total":         total,
		"by_decision":   byDecision,
		"top_rules":     topRules,
		"top_offenders": topOffenders,
	}, nil
}

// RequestCountsBySite menghitung request per site_id sejak sinceTS.
func (s *Storage) RequestCountsBySite(sinceTS float64) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query(
		`SELECT site_id, COUNT(*) c FROM requests
		 WHERE ts >= ? AND site_id != '' GROUP BY site_id`, sinceTS)
	if err != nil {
		return nil, err
	}
	all, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range all {
		out[toString(r["site_id"], "")] = toInt64(r["c"])
	}
	return out, nil
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	default:
		return 0
	}
}

// RecentBlockedIPs mengembalikan IP yang paling sering diblokir.
func (s *Storage) RecentBlockedIPs(sinceTS float64, limit int) ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query(
		`SELECT ip, COUNT(*) c, MAX(ts) last_ts FROM requests
		 WHERE ts >= ? AND decision = 'block' AND ip != ''
		 GROUP BY ip ORDER BY c DESC LIMIT ?`, sinceTS, limit)
	if err != nil {
		return nil, err
	}
	all, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(all))
	for _, r := range all {
		out = append(out, map[string]any{
			"ip": r["ip"], "count": r["c"], "last_ts": r["last_ts"],
		})
	}
	return out, nil
}

// -- agent runs -----------------------------------------------------------

func (s *Storage) LogAgentRun(requestID, backend, decision string, confidence float64,
	reasoning, indicators []any, durationMs float64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rj, err := json.Marshal(reasoning)
	if err != nil {
		return 0, err
	}
	ij, err := json.Marshal(indicators)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.Exec(
		`INSERT INTO agent_runs
		 (request_id, ts, backend, decision, confidence, reasoning, indicators, duration_ms)
		 VALUES (?,?,?,?,?,?,?,?)`,
		requestID, float64(time.Now().UnixNano())/1e9, backend, decision,
		confidence, string(rj), string(ij), durationMs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RecentAgentRuns mengembalikan run agent terbaru; kolom reasoning & indicators
// di-decode dari JSON TEXT menjadi slice (seperti Python).
func (s *Storage) RecentAgentRuns(limit int) ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query(
		"SELECT * FROM agent_runs ORDER BY ts DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	all, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		r["reasoning"] = decodeJSONArray(toString(r["reasoning"], ""))
		r["indicators"] = decodeJSONArray(toString(r["indicators"], ""))
	}
	return all, nil
}

func decodeJSONArray(s string) []any {
	var out []any
	if s == "" {
		return out
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return []any{}
	}
	if out == nil {
		return []any{}
	}
	return out
}

// -- proposed rules -------------------------------------------------------

func (s *Storage) ProposeRule(rule map[string]any, source, note string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rj, err := json.Marshal(rule)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.Exec(
		"INSERT INTO proposed_rules (ts, rule_json, source, note) VALUES (?,?,?,?)",
		float64(time.Now().UnixNano())/1e9, string(rj), source, note)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListProposed mengembalikan usulan aturan berdasar status; tiap item memuat
// key "rule" hasil decode rule_json (seperti Python).
func (s *Storage) ListProposed(status string) ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query(
		"SELECT * FROM proposed_rules WHERE status = ? ORDER BY ts DESC", status)
	if err != nil {
		return nil, err
	}
	all, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		var rule map[string]any
		if err := json.Unmarshal([]byte(toString(r["rule_json"], "")), &rule); err != nil {
			rule = map[string]any{}
		}
		r["rule"] = rule
	}
	return all, nil
}

func (s *Storage) SetProposedStatus(pid int64, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec(
		"UPDATE proposed_rules SET status = ? WHERE id = ?", status, pid)
	return err
}

// -- sites ----------------------------------------------------------------

func (s *Storage) ListSites() ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query("SELECT * FROM sites ORDER BY domain")
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

// GetSite mengembalikan site berdasar id, atau sql.ErrNoRows bila tak ada.
func (s *Storage) GetSite(siteID string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query("SELECT * FROM sites WHERE id = ?", siteID)
	if err != nil {
		return nil, err
	}
	return scanOneRow(rows)
}

// GetSiteByDomain mencari site berdasar domain (dinormalisasi lowercase,
// seperti Python).
func (s *Storage) GetSiteByDomain(domain string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query(
		"SELECT * FROM sites WHERE domain = ?", strings.ToLower(domain))
	if err != nil {
		return nil, err
	}
	return scanOneRow(rows)
}

// UpsertSite menyimpan site dari map (bentuk sama seperti dict Python);
// mengembalikan id site (dibuat acak bila tidak diberikan).
func (s *Storage) UpsertSite(site map[string]any) (string, error) {
	sid := toString(site["id"], "")
	if sid == "" {
		var err error
		sid, err = randomID()
		if err != nil {
			return "", err
		}
	}
	domain := strings.ToLower(toString(site["domain"], ""))
	if domain == "" {
		return "", errors.New("domain wajib diisi")
	}
	bcookies := jsonListText(site["cache_bypass_cookies"], "[]")

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec(
		`INSERT INTO sites
		 (id, domain, upstream_host, upstream_port, upstream_tls,
		  upstream_tls_verify, preserve_host, enabled, agent_enabled,
		  disabled_rules, tls_cert, tls_key, tls_expires_at,
		  ddos_mode, ddos_rps,
		  cache_enabled, cache_ttl, cache_max_entries,
		  cache_max_object_kb, cache_bypass_cookies,
		  recaptcha_enabled, cf_zone_id, blocked_countries, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   domain=excluded.domain, upstream_host=excluded.upstream_host,
		   upstream_port=excluded.upstream_port,
		   upstream_tls=excluded.upstream_tls,
		   upstream_tls_verify=excluded.upstream_tls_verify,
		   preserve_host=excluded.preserve_host,
		   enabled=excluded.enabled,
		   agent_enabled=excluded.agent_enabled,
		   disabled_rules=excluded.disabled_rules,
		   tls_cert=excluded.tls_cert, tls_key=excluded.tls_key,
		   tls_expires_at=excluded.tls_expires_at,
		   ddos_mode=excluded.ddos_mode, ddos_rps=excluded.ddos_rps,
		   cache_enabled=excluded.cache_enabled,
		   cache_ttl=excluded.cache_ttl,
		   cache_max_entries=excluded.cache_max_entries,
		   cache_max_object_kb=excluded.cache_max_object_kb,
		   cache_bypass_cookies=excluded.cache_bypass_cookies,
		   recaptcha_enabled=excluded.recaptcha_enabled,
		   cf_zone_id=excluded.cf_zone_id,
		   blocked_countries=excluded.blocked_countries`,
		sid,
		domain,
		toString(site["upstream_host"], "127.0.0.1"),
		toInt(site["upstream_port"], 8000),
		boolInt(toBool(site["upstream_tls"], false)),
		boolInt(toBool(site["upstream_tls_verify"], true)),
		boolInt(toBool(site["preserve_host"], true)),
		boolInt(toBool(site["enabled"], true)),
		boolInt(toBool(site["agent_enabled"], true)),
		jsonListText(site["disabled_rules"], "[]"),
		toString(site["tls_cert"], ""),
		toString(site["tls_key"], ""),
		toFloat(site["tls_expires_at"], 0),
		boolInt(toBool(site["ddos_mode"], false)),
		toFloat(site["ddos_rps"], 5),
		boolInt(toBool(site["cache_enabled"], false)),
		toInt(site["cache_ttl"], 60),
		toInt(site["cache_max_entries"], 1000),
		toInt(site["cache_max_object_kb"], 2048),
		bcookies,
		boolInt(toBool(site["recaptcha_enabled"], false)),
		toString(site["cf_zone_id"], ""),
		jsonListText(site["blocked_countries"], "[]"),
		float64(time.Now().UnixNano())/1e9,
	)
	if err != nil {
		return "", err
	}
	return sid, nil
}

func (s *Storage) DeleteSite(siteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec("DELETE FROM sites WHERE id = ?", siteID)
	return err
}

// -- ip whitelist/blacklist -----------------------------------------------

func (s *Storage) ListIPEntries() ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query("SELECT * FROM ip_lists ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

// UpsertIPEntry menyimpan entri daftar IP dari map dengan key:
// id, network, list, scope, note, expires_at (boleh nil).
func (s *Storage) UpsertIPEntry(e map[string]any) error {
	id := toString(e["id"], "")
	if id == "" {
		return errors.New("id entri wajib diisi")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec(
		`INSERT INTO ip_lists
		 (id, network, list, scope, note, expires_at, created_at)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   network=excluded.network, list=excluded.list,
		   scope=excluded.scope, note=excluded.note,
		   expires_at=excluded.expires_at`,
		id,
		toString(e["network"], ""),
		toString(e["list"], ""),
		toString(e["scope"], "global"),
		toString(e["note"], ""),
		nullIfNil(e["expires_at"]),
		float64(time.Now().UnixNano())/1e9,
	)
	return err
}

// nullIfNil mengubah nilai nil menjadi NULL SQL (driver menerima nil).
func nullIfNil(v any) any {
	if v == nil {
		return nil
	}
	return v
}

func (s *Storage) DeleteIPEntry(eid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec("DELETE FROM ip_lists WHERE id = ?", eid)
	return err
}

// -- pengaturan umum (key-value) -------------------------------------------

func (s *Storage) GetSetting(key, def string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var val string
	err := s.DB.QueryRow(
		"SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	return val, nil
}

func (s *Storage) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// -- grup IP ----------------------------------------------------------------

func (s *Storage) CreateIPGroup(name, kind, description string) (string, error) {
	if kind != "white" && kind != "black" {
		return "", errors.New("kind harus 'white' atau 'black'")
	}
	gid, err := randomID()
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.DB.Exec(
		`INSERT INTO ip_groups (id, name, kind, description, created_at)
		 VALUES (?,?,?,?,?)`,
		gid, name, kind, strings.TrimSpace(description),
		float64(time.Now().UnixNano())/1e9)
	if err != nil {
		if isUniqueViolation(err) {
			return "", fmt.Errorf("grup '%s' sudah ada", name)
		}
		return "", err
	}
	return gid, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "UNIQUE")
}

func (s *Storage) ListIPGroups() ([]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query("SELECT * FROM ip_groups ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	groups, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	rows, err = s.DB.Query("SELECT group_id, cidr FROM ip_group_members")
	if err != nil {
		return nil, err
	}
	members, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	byGroup := map[string][]string{}
	for _, m := range members {
		gid := toString(m["group_id"], "")
		byGroup[gid] = append(byGroup[gid], toString(m["cidr"], ""))
	}
	for _, g := range groups {
		mm := byGroup[toString(g["id"], "")]
		sort.Strings(mm)
		if mm == nil {
			mm = []string{}
		}
		g["members"] = mm
	}
	return groups, nil
}

// GetIPGroup mengembalikan satu grup beserta members-nya,
// atau sql.ErrNoRows bila tak ada.
func (s *Storage) GetIPGroup(gid string) (map[string]any, error) {
	groups, err := s.ListIPGroups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if toString(g["id"], "") == gid {
			return g, nil
		}
	}
	return nil, sql.ErrNoRows
}

// UpdateIPGroup mengubah nama/deskripsi grup; name/description nil = jangan ubah.
// Mengembalikan false bila tidak ada field diubah atau grup tak ditemukan.
func (s *Storage) UpdateIPGroup(gid string, name, description *string) (bool, error) {
	var sets []string
	var vals []any
	if name != nil {
		sets = append(sets, "name = ?")
		vals = append(vals, strings.TrimSpace(*name))
	}
	if description != nil {
		sets = append(sets, "description = ?")
		vals = append(vals, strings.TrimSpace(*description))
	}
	if len(sets) == 0 {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vals = append(vals, gid)
	res, err := s.DB.Exec(
		fmt.Sprintf("UPDATE ip_groups SET %s WHERE id = ?", strings.Join(sets, ", ")),
		vals...)
	if err != nil {
		if isUniqueViolation(err) && name != nil {
			return false, fmt.Errorf("grup '%s' sudah ada", strings.TrimSpace(*name))
		}
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Storage) DeleteIPGroup(gid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.DB.Exec(
		"DELETE FROM ip_group_members WHERE group_id = ?", gid); err != nil {
		return err
	}
	_, err := s.DB.Exec("DELETE FROM ip_groups WHERE id = ?", gid)
	return err
}

// AddGroupMember menambah CIDR ke grup; CIDR dinormalisasi
// (mis. "198.51.100.7" -> "198.51.100.7/32") seperti ipaddress Python.
// Mengembalikan error bila CIDR tak valid atau grup tak ditemukan.
func (s *Storage) AddGroupMember(gid, cidr string) (string, error) {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("CIDR tidak valid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var exists string
	err = s.DB.QueryRow("SELECT id FROM ip_groups WHERE id = ?", gid).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("grup tidak ditemukan")
	}
	if err != nil {
		return "", err
	}
	_, err = s.DB.Exec(
		`INSERT OR IGNORE INTO ip_group_members (group_id, cidr) VALUES (?, ?)`,
		gid, normalized)
	if err != nil {
		return "", err
	}
	return normalized, nil
}

// normalizeCIDR memvalidasi & menormalisasi CIDR seperti
// ipaddress.ip_network(cidr, strict=False) di Python.
func normalizeCIDR(cidr string) (string, error) {
	c := strings.TrimSpace(cidr)
	if p, err := netip.ParsePrefix(c); err == nil {
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(c)
	if err != nil {
		// dukung notasi lama Go juga sebelum menyerah
		if _, _, err2 := net.ParseCIDR(c); err2 == nil {
			if p2, err3 := netip.ParsePrefix(c); err3 == nil {
				return p2.Masked().String(), nil
			}
		}
		return "", err
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

func (s *Storage) RemoveGroupMember(gid, cidr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec(
		"DELETE FROM ip_group_members WHERE group_id = ? AND cidr = ?",
		gid, strings.TrimSpace(cidr))
	return err
}

// -- geo cache --------------------------------------------------------------

func (s *Storage) GeoGet(ip string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query("SELECT * FROM geo_cache WHERE ip = ?", ip)
	if err != nil {
		return nil, err
	}
	return scanOneRow(rows)
}

// GeoSet menyimpan cache geo; lat/lon nil berarti NULL (seperti Python).
func (s *Storage) GeoSet(ip, country, city string, lat, lon *float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var latV, lonV any
	if lat != nil {
		latV = *lat
	}
	if lon != nil {
		lonV = *lon
	}
	_, err := s.DB.Exec(
		`INSERT INTO geo_cache (ip, country, city, lat, lon, ts)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET
		   country=excluded.country, city=excluded.city,
		   lat=excluded.lat, lon=excluded.lon, ts=excluded.ts`,
		ip, country, city, latV, lonV,
		float64(time.Now().UnixNano())/1e9)
	return err
}

// -- reputasi IP ------------------------------------------------------------

func (s *Storage) GetIP(ip string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.DB.Query("SELECT * FROM ip_reputation WHERE ip = ?", ip)
	if err != nil {
		return nil, err
	}
	return scanOneRow(rows)
}

// UpsertIP menyimpan status reputasi IP; blockedUntil nil berarti NULL.
func (s *Storage) UpsertIP(ip string, strikes int, windowStart float64, blockedUntil *float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var bu any
	if blockedUntil != nil {
		bu = *blockedUntil
	}
	_, err := s.DB.Exec(
		`INSERT INTO ip_reputation (ip, strikes, window_start, blocked_until)
		 VALUES (?,?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET
		   strikes=excluded.strikes, window_start=excluded.window_start,
		   blocked_until=excluded.blocked_until`,
		ip, strikes, windowStart, bu)
	return err
}

// -- custom rules -----------------------------------------------------------
//
// Catatan penyimpangan dari Python: di Python custom rules TIDAK disimpan di
// SQLite melainkan di file dataDir/custom_rules.json (dikelola learner.py).
// Method ini membaca file tersebut agar API dashboard Go bisa menampilkannya.

func (s *Storage) ListCustomRules() ([]map[string]any, error) {
	path := filepath.Join(s.dataDir, "custom_rules.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var rules []map[string]any
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []map[string]any{}
	}
	return rules, nil
}
