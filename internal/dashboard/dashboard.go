// Package dashboard: HTTP JSON API + serve SPA Svelte untuk admin Perisai WAF.
//
// Port dari perisai/dashboard.py (Python): bentuk JSON tiap endpoint dibuat
// PERSIS agar SPA (ui/dist) berjalan tanpa perubahan. Aturan keras yang ikut
// di-port: API key/token/secret tidak pernah dikirim utuh ke browser (hanya
// flag api_key_set / api_token_set / secret_key_set), dan perubahan config
// via API berlaku langsung (in-memory) + persist ke file YAML.
package dashboard

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/auth"
	"github.com/willy911/perisai-waf/internal/cache"
	"github.com/willy911/perisai-waf/internal/cloudflare"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/geo"
	"github.com/willy911/perisai-waf/internal/iplists"
	"github.com/willy911/perisai-waf/internal/learner"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
	"github.com/willy911/perisai-waf/internal/tlscerts"
)

// sessionTTLDetik adalah umur session login (12 jam, seperti Python).
const sessionTTLDetik = 12 * 3600

// lockPesanDetik dipakai di pesan 429 throttle (kunci 5 menit, seperti Python).
const lockPesanDetik = 300

// TLSReloader diimplementasikan oleh server proxy agar upload sertifikat bisa
// me-reload TLS SNI tanpa restart. Bila tidak dipasang (extra tidak diberi),
// upload/hapus sertifikat melaporkan tls_active=false & need_restart=true —
// sama seperti Python saat proxy_server tidak ada.
type TLSReloader interface {
	ReloadTLS() error
}

// DisabledSync diimplementasikan oleh server proxy agar toggle rule di
// dashboard langsung berlaku di pipeline triase tanpa restart.
type DisabledSync interface {
	SetRuleDisabled(ruleID string, disabled bool) bool
}

// SiteReloader diimplementasikan oleh server proxy agar perubahan data
// site (tambah/ubah/hapus, DDoS, reCAPTCHA, geo-blocking) langsung
// berlaku tanpa restart.
type SiteReloader interface {
	ReloadSites() error
}

// Dashboard adalah HTTP handler admin: JSON API (token auth) + SPA statis.
type Dashboard struct {
	cfg   *config.WAFConfig
	store *storage.Storage
	orch  *agent.Orchestrator
	eng   *rules.Engine
	spa   fs.FS

	sessions *auth.SessionStore
	throttle *auth.LoginThrottle

	ipl   *iplists.IPLists
	cache *cache.Cache
	geo   *geo.Geo
	tls   TLSReloader

	disSync DisabledSync
	siteRel SiteReloader

	mu       sync.Mutex
	disabled map[string]bool // id rule yang dimatikan (global)
}

// New membuat Dashboard. spaFS adalah filesystem ui/dist (di-embed di
// cmd/perisai via embed.FS lalu diteruskan ke sini); boleh nil bila UI tidak
// tersedia. extra menerima dependensi opsional: *iplists.IPLists,
// *cache.Cache, *geo.Geo, dan TLSReloader — yang tidak diberikan dibuatkan
// default dari cfg/store.
func New(cfg *config.WAFConfig, store *storage.Storage, orch *agent.Orchestrator,
	eng *rules.Engine, spaFS fs.FS, extra ...any) *Dashboard {
	d := &Dashboard{
		cfg:      cfg,
		store:    store,
		orch:     orch,
		eng:      eng,
		spa:      spaFS,
		sessions: auth.NewSessionStore(),
		throttle: auth.NewLoginThrottle(),
		disabled: map[string]bool{},
	}
	for _, e := range extra {
		switch v := e.(type) {
		case *iplists.IPLists:
			d.ipl = v
		case *cache.Cache:
			d.cache = v
		case *geo.Geo:
			d.geo = v
		case TLSReloader:
			d.tls = v
		case DisabledSync:
			d.disSync = v
		case SiteReloader:
			d.siteRel = v
		}
	}
	if d.ipl == nil {
		d.ipl = iplists.New(store)
	}
	if d.cache == nil {
		d.cache = cache.New()
	}
	if d.geo == nil {
		d.geo = geo.New(cfg.Geo, cfg.DataDir, store)
	}
	d.disabled = d.loadDisabled()
	return d
}

// loadDisabled membaca daftar rule global yang dimatikan dari settings
// (seperti _load_global_disabled di waf.py Python).
func (d *Dashboard) loadDisabled() map[string]bool {
	out := map[string]bool{}
	raw, err := d.store.GetSetting("disabled_rules", "[]")
	if err != nil {
		return out
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return out
	}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// DisabledRules mengembalikan id rule global yang sedang dimatikan
// (terurut). Dipakai pipeline WAF saat triase agar toggle dashboard
// benar-benar berlaku — padanan waf.global_disabled_rules di Python.
func (d *Dashboard) DisabledRules() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	ids := make([]string, 0, len(d.disabled))
	for id := range d.disabled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// setRuleDisabled menyalakan/mematikan satu rule global dan persist ke
// settings (seperti set_rule_disabled di waf.py Python). Mengembalikan false
// bila id rule tidak dikenal.
func (d *Dashboard) setRuleDisabled(ruleID string, disabled bool) bool {
	found := false
	for _, r := range d.eng.Rules() {
		if r.ID == ruleID {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	d.mu.Lock()
	if disabled {
		d.disabled[ruleID] = true
	} else {
		delete(d.disabled, ruleID)
	}
	ids := make([]string, 0, len(d.disabled))
	for id := range d.disabled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sync := d.disSync
	d.mu.Unlock()
	raw, _ := json.Marshal(ids)
	_ = d.store.SetSetting("disabled_rules", string(raw))
	// Teruskan ke pipeline proxy agar berlaku langsung tanpa restart.
	if sync != nil {
		sync.SetRuleDisabled(ruleID, disabled)
	}
	return true
}

func (d *Dashboard) isDisabled(ruleID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.disabled[ruleID]
}

// Handler membangun http.Handler lengkap (dipakai http.ServeMux di cmd).
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	// Publik: login / logout (logout cukup mencabut token bila ada).
	mux.HandleFunc("POST /api/login", d.handleLogin)
	mux.HandleFunc("POST /api/logout", d.handleLogout)

	g := d.requireAuth // pembungkus auth untuk endpoint privat

	// GET privat.
	mux.HandleFunc("GET /api/stats", g(d.handleStats))
	mux.HandleFunc("GET /api/requests", g(d.handleRequests))
	mux.HandleFunc("GET /api/agent-runs", g(d.handleAgentRuns))
	mux.HandleFunc("GET /api/proposed", g(d.handleProposed))
	mux.HandleFunc("GET /api/agent/test", g(d.handleAgentTest))
	mux.HandleFunc("GET /api/systemone/test", g(d.handleSystemOneTest))
	mux.HandleFunc("GET /api/attack-map", g(d.handleAttackMap))
	mux.HandleFunc("GET /api/iplists", g(d.handleIPLists))
	mux.HandleFunc("GET /api/ip-groups", g(d.handleIPGroups))
	mux.HandleFunc("GET /api/ip-groups/{id}", g(d.handleIPGroupGet))
	mux.HandleFunc("GET /api/sites", g(d.handleSites))
	mux.HandleFunc("GET /api/sites/{id}", g(d.handleSiteGet))
	mux.HandleFunc("GET /api/rules", g(d.handleRules))
	mux.HandleFunc("GET /api/ai-config", g(d.handleAIConfigGet))
	mux.HandleFunc("GET /api/systemone-config", g(d.handleSystemOneConfigGet))
	mux.HandleFunc("GET /api/cache/config", g(d.handleCacheConfigGet))
	mux.HandleFunc("GET /api/cache/stats", g(d.handleCacheStats))
	mux.HandleFunc("GET /api/recaptcha/config", g(d.handleRecaptchaGet))
	mux.HandleFunc("GET /api/cf/config", g(d.handleCFConfigGet))
	mux.HandleFunc("GET /api/cf/zones", g(d.handleCFZones))
	mux.HandleFunc("GET /api/cf/stats", g(d.handleCFStats))
	mux.HandleFunc("GET /api/terminal/config", g(d.handleTerminalConfig))
	// Websocket terminal: auth dicek manual di dalam handler (sebelum upgrade).
	mux.HandleFunc("GET /api/terminal/ws", d.handleTerminalWS)

	// POST privat.
	mux.HandleFunc("POST /api/proposed/{id}/approve", g(d.handleProposedApprove))
	mux.HandleFunc("POST /api/proposed/{id}/reject", g(d.handleProposedReject))
	mux.HandleFunc("POST /api/sites", g(d.handleSiteUpsert))
	mux.HandleFunc("POST /api/sites/{id}/toggle", g(d.handleSiteToggle))
	mux.HandleFunc("POST /api/sites/{id}/ddos", g(d.handleSiteDDoS))
	mux.HandleFunc("POST /api/sites/{id}/cert", g(d.handleSiteCertUpload))
	mux.HandleFunc("POST /api/sites/{id}/recaptcha", g(d.handleSiteRecaptcha))
	mux.HandleFunc("POST /api/sites/{id}/geoblock", g(d.handleSiteGeoBlock))
	mux.HandleFunc("POST /api/rules/{id}/toggle", g(d.handleRuleToggle))
	mux.HandleFunc("POST /api/ai-config", g(d.handleAIConfigPost))
	mux.HandleFunc("POST /api/ai-models", g(d.handleAIModels))
	mux.HandleFunc("POST /api/systemone-config", g(d.handleSystemOneConfigPost))
	mux.HandleFunc("POST /api/cache/config", g(d.handleCacheConfigPost))
	mux.HandleFunc("POST /api/cache/purge", g(d.handleCachePurge))
	mux.HandleFunc("POST /api/iplists", g(d.handleIPListAdd))
	mux.HandleFunc("POST /api/ip-groups", g(d.handleIPGroupCreate))
	mux.HandleFunc("POST /api/ip-groups/{id}/members", g(d.handleIPGroupAddMember))
	mux.HandleFunc("POST /api/recaptcha/config", g(d.handleRecaptchaPost))
	mux.HandleFunc("POST /api/cf/config", g(d.handleCFConfigPost))
	mux.HandleFunc("POST /api/cf/purge", g(d.handleCFPurge))

	// PUT privat.
	mux.HandleFunc("PUT /api/ip-groups/{id}", g(d.handleIPGroupUpdate))

	// DELETE privat.
	mux.HandleFunc("DELETE /api/iplists/{id}", g(d.handleIPListDelete))
	mux.HandleFunc("DELETE /api/ip-groups/{id}", g(d.handleIPGroupDelete))
	mux.HandleFunc("DELETE /api/ip-groups/{id}/members", g(d.handleIPGroupDelMember))
	mux.HandleFunc("DELETE /api/sites/{id}", g(d.handleSiteDelete))
	mux.HandleFunc("DELETE /api/sites/{id}/cert", g(d.handleSiteCertDelete))

	// Catch-all: /api/* tak dikenal -> 404 JSON; selain itu serve SPA.
	mux.HandleFunc("/", d.handleSPA)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeErr(w, http.StatusInternalServerError, fmt.Sprint(rec))
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

// -- helper HTTP & JSON ----------------------------------------------------

// writeJSON menulis respons JSON (Content-Type seperti Python).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // seperti json.dumps(ensure_ascii=False)
	_ = enc.Encode(v)
}

// writeErr menulis {"error": msg} dengan status HTTP yang diminta.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// writeOK menulis {"ok": true} plus field tambahan opsional.
func writeOK(w http.ResponseWriter, extra map[string]any) {
	out := map[string]any{"ok": true}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

const maxBodyBytes = 10 << 20 // 10 MiB, batas body JSON dashboard

// readJSON membaca body sebagai map JSON. Body kosong -> map kosong
// (seperti Python yang memakai b"{}" bila Content-Length 0).
func readJSON(r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("bukan objek JSON")
	}
	return m, nil
}

// -- auth ------------------------------------------------------------------

// extractToken mengambil token dari ?token= atau header Authorization: Bearer
// (seperti _extract_token di dashboard.py Python).
func (d *Dashboard) extractToken(r *http.Request) string {
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}
	ah := r.Header.Get("Authorization")
	if len(ah) > 7 && strings.EqualFold(ah[:7], "bearer ") {
		return strings.TrimSpace(ah[7:])
	}
	return ""
}

// authed memeriksa token: session login dulu, lalu token API statis dari
// config (seperti _authed di Python).
func (d *Dashboard) authed(r *http.Request) bool {
	token := d.extractToken(r)
	if token == "" {
		return false
	}
	if d.sessions.Validate(token) {
		return true
	}
	expected := d.cfg.Dashboard.Token
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// requireAuth membungkus handler agar menolak request tanpa token (401).
func (d *Dashboard) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.authed(r) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// clientIP mengambil IP klien dari RemoteAddr (untuk LoginThrottle).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleLogin: POST /api/login {username, password} -> {ok, token, ...}.
// Publik (tanpa auth). Anti brute-force: 5x gagal -> kunci 5 menit per IP.
func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ip := clientIP(r)
	if d.throttle.Locked(ip) {
		writeErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("terlalu banyak percobaan gagal, coba lagi dalam %d detik",
				lockPesanDetik))
		return
	}
	dc := d.cfg.Dashboard
	if dc.PasswordHash == "" {
		writeErr(w, http.StatusServiceUnavailable,
			"login belum dikonfigurasi — jalankan di server: "+
				"perisai-setpassword --config config.yaml")
		return
	}
	username := pyStr(body["username"])
	password := pyStr(body["password"])
	ok := subtle.ConstantTimeCompare([]byte(username), []byte(dc.Username)) == 1 &&
		auth.CheckPassword(password, dc.PasswordHash)
	if ok {
		d.throttle.RegisterSuccess(ip)
		token, terr := d.sessions.Create(dc.Username)
		if terr != nil {
			writeErr(w, http.StatusInternalServerError, "gagal membuat sesi")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "token": token,
			"expires_in": sessionTTLDetik, "username": dc.Username,
		})
		return
	}
	d.throttle.RegisterFailure(ip)
	time.Sleep(300 * time.Millisecond) // jeda kecil lawan timing attack
	writeErr(w, http.StatusUnauthorized, "username atau password salah")
}

// handleLogout: POST /api/logout — cabut session token (publik, seperti Python).
func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	d.sessions.Invalidate(d.extractToken(r))
	writeOK(w, nil)
}

// -- serve SPA ---------------------------------------------------------------

var spaMIME = map[string]string{
	".html":  "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".woff2": "font/woff2",
	".woff":  "font/woff",
	".ttf":   "font/ttf",
}

// handleSPA menyajikan ui/dist: file aset langsung, route client-side fallback
// ke index.html. Cegah path traversal. /api/* tak dikenal -> 404 JSON.
func (d *Dashboard) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if d.spa == nil {
		http.Error(w, "UI belum tersedia", http.StatusNotFound)
		return
	}
	rel := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if rel != "" && !strings.Contains(rel, "..") {
		if data, ctype, ok := d.spaRead(rel); ok {
			d.spaServe(w, data, ctype)
			return
		}
	}
	// SPA fallback: semua route non-file -> index.html
	data, _, ok := d.spaRead("index.html")
	if !ok {
		http.Error(w, "UI belum tersedia", http.StatusNotFound)
		return
	}
	d.spaServe(w, data, "text/html; charset=utf-8")
}

// spaRead membaca satu file dari filesystem SPA.
func (d *Dashboard) spaRead(name string) (data []byte, ctype string, ok bool) {
	f, err := d.spa.Open(name)
	if err != nil {
		return nil, "", false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return nil, "", false
	}
	data, err = io.ReadAll(io.LimitReader(f, 50<<20))
	if err != nil {
		return nil, "", false
	}
	ctype = spaMIME[strings.ToLower(path.Ext(name))]
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	if name == "index.html" {
		ctype = "text/html; charset=utf-8"
	}
	return data, ctype, true
}

func (d *Dashboard) spaServe(w http.ResponseWriter, data []byte, ctype string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// -- konversi nilai (semantik Python) -----------------------------------------

// pyStr meniru str() Python untuk nilai hasil decode JSON.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// fieldStr mengambil string field body; default bila key absen
// (seperti str(data.get(key, default)).strip() di Python).
func fieldStr(body map[string]any, key, def string) string {
	v, ok := body[key]
	if !ok {
		return def
	}
	return strings.TrimSpace(pyStr(v))
}

// pyBool meniru bool() Python untuk nilai hasil decode JSON / baris DB.
func pyBool(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0
	case float32:
		return t != 0
	case int:
		return t != 0
	case int8:
		return t != 0
	case int16:
		return t != 0
	case int32:
		return t != 0
	case int64:
		return t != 0
	case uint, uint8, uint16, uint32, uint64:
		return t != 0
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

// toIntE mengkonversi nilai JSON ke int (seperti int() Python untuk
// angka/string angka). ok=false bila tidak bisa dikonversi.
func toIntE(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case string:
		s := strings.TrimSpace(t)
		if n, err := strconv.Atoi(s); err == nil {
			return n, true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int(f), true
		}
		return 0, false
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return int(n), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// toFloatE mengkonversi nilai JSON ke float64. ok=false bila gagal.
func toFloatE(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// randomID12 membuat id acak 12 karakter hex (seperti uuid4().hex[:12]).
func randomID12() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// normalizeNetwork memvalidasi & menormalisasi IP/CIDR seperti
// ipaddress.ip_network(s, strict=False): IP tunggal -> /32 (atau /128),
// bit host di-mask ("10.0.0.5/24" -> "10.0.0.0/24").
func normalizeNetwork(s string) (string, bool) {
	c := strings.TrimSpace(s)
	if c == "" {
		return "", false
	}
	if p, err := netip.ParsePrefix(c); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(c); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}

// flipInt membalik flag 0/1 ala Python (0 if x else 1).
func flipInt(v any) int {
	if pyBool(v) {
		return 0
	}
	return 1
}

// -- handler GET -------------------------------------------------------------

func nowSec() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// queryLimit mengambil ?limit= (default 100, maks 500) seperti Python.
func queryLimit(r *http.Request) (int, error) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, err
		}
		limit = n
	}
	if limit > 500 {
		limit = 500
	}
	if limit < 0 {
		limit = 0
	}
	return limit, nil
}

// handleStats: GET /api/stats — statistik 24 jam terakhir + rules_loaded.
func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := d.store.Stats(nowSec() - 86400)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st["rules_loaded"] = len(d.eng.Rules())
	writeJSON(w, http.StatusOK, st)
}

// handleRequests: GET /api/requests?limit= — log permintaan terbaru.
func (d *Dashboard) handleRequests(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows, err := d.store.RecentRequests(limit, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleAgentRuns: GET /api/agent-runs?limit= — riwayat penalaran AI.
func (d *Dashboard) handleAgentRuns(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows, err := d.store.RecentAgentRuns(limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleProposed: GET /api/proposed — usulan aturan auto-learning (pending).
func (d *Dashboard) handleProposed(w http.ResponseWriter, r *http.Request) {
	rows, err := d.store.ListProposed("pending")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleAgentTest: GET /api/agent/test — uji koneksi backend LLM.
func (d *Dashboard) handleAgentTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.orch.TestLLM())
}

// handleSystemOneTest: GET /api/systemone/test — uji koneksi System One.
func (d *Dashboard) handleSystemOneTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.orch.TestSystemOne())
}

// handleAttackMap: GET /api/attack-map?hours= — titik serangan (lat/lon).
func (d *Dashboard) handleAttackMap(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if s := r.URL.Query().Get("hours"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		hours = n
	}
	if hours > 168 {
		hours = 168
	}
	rows, err := d.store.RecentBlockedIPs(nowSec()-float64(hours)*3600, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		ip := pyStr(row["ip"])
		country, city, lat, lon := d.geo.Lookup(ip)
		if lat == 0 && lon == 0 {
			continue // tidak ada data geo (seperti resolve() -> None)
		}
		out = append(out, map[string]any{
			"ip": ip, "count": row["count"], "last_ts": row["last_ts"],
			"country": country, "city": city, "lat": lat, "lon": lon,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleIPLists: GET /api/iplists — daftar whitelist/blacklist.
func (d *Dashboard) handleIPLists(w http.ResponseWriter, r *http.Request) {
	rows, err := d.store.ListIPEntries()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleIPGroups: GET /api/ip-groups — daftar grup IP.
func (d *Dashboard) handleIPGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := d.store.ListIPGroups()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleIPGroupGet: GET /api/ip-groups/{id} — satu grup beserta members.
func (d *Dashboard) handleIPGroupGet(w http.ResponseWriter, r *http.Request) {
	g, err := d.store.GetIPGroup(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "grup tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// handleSites: GET /api/sites — daftar site + requests_24h.
func (d *Dashboard) handleSites(w http.ResponseWriter, r *http.Request) {
	sites, err := d.store.ListSites()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	counts, err := d.store.RequestCountsBySite(nowSec() - 86400)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sites == nil {
		sites = []map[string]any{}
	}
	for _, s := range sites {
		s["requests_24h"] = counts[pyStr(s["id"])]
	}
	writeJSON(w, http.StatusOK, sites)
}

// handleSiteGet: GET /api/sites/{id} — satu site + requests_24h.
func (d *Dashboard) handleSiteGet(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	counts, err := d.store.RequestCountsBySite(nowSec() - 86400)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	site["requests_24h"] = counts[pyStr(site["id"])]
	writeJSON(w, http.StatusOK, site)
}

// handleRules: GET /api/rules — daftar signature + flag disabled.
func (d *Dashboard) handleRules(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0)
	for _, rule := range d.eng.Rules() {
		out = append(out, map[string]any{
			"id": rule.ID, "name": rule.Name, "category": rule.Category,
			"severity": rule.Severity, "weight": rule.Weight,
			"disabled": d.isDisabled(rule.ID),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// aiConfigView: snapshot pengaturan AI untuk UI (API key tak pernah utuh).
func (d *Dashboard) aiConfigView() map[string]any {
	llm := d.cfg.Agent.LLM
	return map[string]any{
		"backend":        d.cfg.Agent.Backend,
		"min_confidence": d.cfg.Agent.MinConfidence,
		"llm": map[string]any{
			"base_url":    llm.BaseURL,
			"model":       llm.Model,
			"timeout":     llm.Timeout,
			"api_key_set": llm.APIKey != "",
		},
	}
}

// handleAIConfigGet: GET /api/ai-config.
func (d *Dashboard) handleAIConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.aiConfigView())
}

// systemOneConfigView: snapshot pengaturan System One (API key tak pernah utuh).
func (d *Dashboard) systemOneConfigView() map[string]any {
	s1 := d.cfg.Agent.SystemOne
	return map[string]any{
		"enabled":     s1.Enabled,
		"endpoint":    s1.Endpoint,
		"model":       s1.Model,
		"timeout":     s1.Timeout,
		"api_key_set": bool(s1.APIKey != ""),
	}
}

// handleSystemOneConfigGet: GET /api/systemone-config.
func (d *Dashboard) handleSystemOneConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.systemOneConfigView())
}

// handleCacheConfigGet: GET /api/cache/config?site_id= — konfigurasi cache
// per site.
func (d *Dashboard) handleCacheConfigGet(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.URL.Query().Get("site_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	bypass := []string{}
	if raw := pyStr(site["cache_bypass_cookies"]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &bypass)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"site_id":        site["id"],
		"enabled":        pyBool(site["cache_enabled"]),
		"ttl":            site["cache_ttl"],
		"max_entries":    site["cache_max_entries"],
		"max_object_kb":  site["cache_max_object_kb"],
		"bypass_cookies": bypass,
	})
}

// handleCacheStats: GET /api/cache/stats?site_id= — statistik cache.
func (d *Dashboard) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	st := d.cache.Stats(r.URL.Query().Get("site_id"))
	writeJSON(w, http.StatusOK, map[string]any{
		"hits":      st.Hits,
		"misses":    st.Misses,
		"hit_ratio": st.HitRatio,
		"entries":   st.Entries,
		"bytes":     st.Bytes,
	})
}

// handleRecaptchaGet: GET /api/recaptcha/config — pengaturan reCAPTCHA
// global (secret tidak pernah ke browser).
func (d *Dashboard) handleRecaptchaGet(w http.ResponseWriter, r *http.Request) {
	rc := d.cfg.Recaptcha
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":        rc.Enabled,
		"site_key":       rc.SiteKey,
		"site_key_set":   rc.SiteKey != "",
		"secret_key_set": rc.SecretKey != "",
		"mode":           rc.Mode,
	})
}

// handleCFConfigGet: GET /api/cf/config — status token + mapping zone.
func (d *Dashboard) handleCFConfigGet(w http.ResponseWriter, r *http.Request) {
	sites, err := d.store.ListSites()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	zones := make([]map[string]any, 0, len(sites))
	for _, s := range sites {
		zones = append(zones, map[string]any{
			"site_id": s["id"], "domain": s["domain"],
			"zone_id": s["cf_zone_id"],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_token_set": d.cfg.Cloudflare.APIToken != "",
		"zones":         zones,
	})
}

// handleCFZones: GET /api/cf/zones — daftar zone di akun Cloudflare
// (tambahan di luar dashboard.py; dipakai UI untuk mapping zone).
func (d *Dashboard) handleCFZones(w http.ResponseWriter, r *http.Request) {
	zones, err := cloudflare.ListZones(d.cfg.Cloudflare.APIToken)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if zones == nil {
		zones = []cloudflare.Zone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zones": zones})
}

// handleCFStats: GET /api/cf/stats?site_id=&minutes= — statistik zone
// (di-proxy server-side agar token tidak ke browser).
func (d *Dashboard) handleCFStats(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.URL.Query().Get("site_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	minutes := 1440
	if s := r.URL.Query().Get("minutes"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			minutes = n
		}
	}
	if minutes < 15 {
		minutes = 15
	}
	if minutes > 10080 {
		minutes = 10080
	}
	st, err := cloudflare.ZoneStats(d.cfg.Cloudflare.APIToken,
		pyStr(site["cf_zone_id"]), minutes)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// -- validasi config AI -------------------------------------------------------

type aiClean struct {
	backend string
	baseURL string
	model   string
	timeout int
	minConf float64
	apiKey  *string // nil = jangan ubah
}

// validateAIConfig memvalidasi body POST /api/ai-config (port persis
// _validate_ai_config di dashboard.py).
func validateAIConfig(body map[string]any) (aiClean, string) {
	var c aiClean
	backend := fieldStr(body, "backend", "auto")
	if backend != "auto" && backend != "heuristic" &&
		backend != "llm" && backend != "systemone" {
		return c, "backend harus salah satu: auto, heuristic, llm, systemone"
	}
	c.backend = backend
	baseURL := fieldStr(body, "base_url", "")
	if len(baseURL) > 200 {
		return c, "base_url terlalu panjang (maks 200 karakter)"
	}
	if baseURL != "" {
		low := strings.ToLower(baseURL)
		if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
			return c, "base_url harus diawali http:// atau https://"
		}
	}
	if backend == "llm" && baseURL == "" {
		return c, "base_url wajib diisi bila backend = llm"
	}
	c.baseURL = baseURL
	model := fieldStr(body, "model", "")
	if model == "" || len(model) > 120 {
		return c, "model wajib diisi (maks 120 karakter)"
	}
	c.model = model
	timeout := 20
	if v, ok := body["timeout"]; ok {
		n, ok := toIntE(v)
		if !ok {
			return c, "timeout harus angka"
		}
		timeout = n
	}
	if timeout < 5 || timeout > 120 {
		return c, "timeout harus 5–120 detik"
	}
	c.timeout = timeout
	minConf := 0.55
	if v, ok := body["min_confidence"]; ok {
		f, ok := toFloatE(v)
		if !ok {
			return c, "min_confidence harus angka"
		}
		minConf = f
	}
	if minConf < 0.0 || minConf > 1.0 {
		return c, "min_confidence harus 0–1"
	}
	c.minConf = minConf
	// api_key: absen/kosong = jangan ubah; clear_api_key = kosongkan eksplisit.
	if pyBool(body["clear_api_key"]) {
		empty := ""
		c.apiKey = &empty
	} else if v, ok := body["api_key"]; ok && pyStr(v) != "" {
		s := pyStr(v)
		c.apiKey = &s
	}
	return c, ""
}

type systemOneClean struct {
	enabled  bool
	endpoint string
	model    string
	timeout  int
	apiKey   *string // nil = jangan ubah
}

// validateSystemOneConfig memvalidasi body POST /api/systemone-config (port
// persis _validate_systemone_config di dashboard.py).
func validateSystemOneConfig(body map[string]any) (systemOneClean, string) {
	var c systemOneClean
	c.enabled = true
	if v, ok := body["enabled"]; ok {
		c.enabled = pyBool(v)
	}
	endpoint := fieldStr(body, "endpoint", "")
	if len(endpoint) > 200 {
		return c, "endpoint terlalu panjang (maks 200 karakter)"
	}
	if endpoint != "" {
		low := strings.ToLower(endpoint)
		if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
			return c, "endpoint harus diawali http:// atau https://"
		}
	}
	if c.enabled && endpoint == "" {
		return c, "endpoint wajib diisi bila System One diaktifkan"
	}
	c.endpoint = endpoint
	model := fieldStr(body, "model", "")
	if model == "" || len(model) > 120 {
		return c, "model wajib diisi (maks 120 karakter)"
	}
	c.model = model
	timeout := 10
	if v, ok := body["timeout"]; ok {
		n, ok := toIntE(v)
		if !ok {
			return c, "timeout harus angka"
		}
		timeout = n
	}
	if timeout < 5 || timeout > 120 {
		return c, "timeout harus 5–120 detik"
	}
	c.timeout = timeout
	if pyBool(body["clear_api_key"]) {
		empty := ""
		c.apiKey = &empty
	} else if v, ok := body["api_key"]; ok && pyStr(v) != "" {
		s := pyStr(v)
		c.apiKey = &s
	}
	return c, ""
}

// handleAIConfigPost: POST /api/ai-config — simpan pengaturan AI agent
// (berlaku langsung, tanpa restart).
func (d *Dashboard) handleAIConfigPost(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	clean, msg := validateAIConfig(body)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	// Terapkan ke config in-memory (backend membaca objek yang sama ->
	// berlaku langsung tanpa restart).
	d.cfg.Agent.Backend = clean.backend
	d.cfg.Agent.MinConfidence = clean.minConf
	llm := &d.cfg.Agent.LLM
	llm.BaseURL = clean.baseURL
	llm.Model = clean.model
	llm.Timeout = clean.timeout
	if clean.apiKey != nil {
		llm.APIKey = *clean.apiKey
	}
	persisted := false
	if d.cfg.ConfigPath != "" {
		if err := config.SaveLLMConfig(d.cfg.ConfigPath, clean.backend,
			clean.minConf, clean.baseURL, clean.model, clean.timeout,
			clean.apiKey); err != nil {
			writeErr(w, http.StatusInternalServerError,
				"gagal menyimpan: "+err.Error())
			return
		}
		persisted = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "persisted": persisted, "restart_needed": false,
		"config": d.aiConfigView(),
	})
}

// handleSystemOneConfigPost: POST /api/systemone-config — simpan pengaturan
// System One (berlaku langsung).
func (d *Dashboard) handleSystemOneConfigPost(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	clean, msg := validateSystemOneConfig(body)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	s1 := &d.cfg.Agent.SystemOne
	s1.Enabled = clean.enabled
	s1.Endpoint = clean.endpoint
	s1.Model = clean.model
	s1.Timeout = clean.timeout
	if clean.apiKey != nil {
		s1.APIKey = *clean.apiKey
	}
	persisted := false
	if d.cfg.ConfigPath != "" {
		if err := config.SaveSystemOneConfig(d.cfg.ConfigPath, clean.enabled,
			clean.endpoint, clean.model, clean.timeout,
			clean.apiKey); err != nil {
			writeErr(w, http.StatusInternalServerError,
				"gagal menyimpan: "+err.Error())
			return
		}
		persisted = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "persisted": persisted, "restart_needed": false,
		"config": d.systemOneConfigView(),
	})
}

// handleAIModels: POST /api/ai-models — ambil daftar model dari endpoint
// (server-side agar API key tidak terekspos ke browser & bebas CORS).
func (d *Dashboard) handleAIModels(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	baseURL := fieldStr(body, "base_url", "")
	if baseURL == "" {
		baseURL = d.cfg.Agent.LLM.BaseURL
	}
	apiKey := fieldStr(body, "api_key", "")
	if apiKey == "" {
		apiKey = d.cfg.Agent.LLM.APIKey
	}
	low := strings.ToLower(baseURL)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		writeErr(w, http.StatusBadRequest, "base_url tidak valid")
		return
	}
	models, err := agent.FetchModels(baseURL, apiKey)
	if err != nil {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		writeJSON(w, http.StatusBadGateway,
			map[string]any{"ok": false, "error": msg})
		return
	}
	if models == nil {
		models = []map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "models": models, "count": len(models),
	})
}

// -- handler POST/PUT/DELETE --------------------------------------------------

// handleProposedApprove: POST /api/proposed/{id}/approve — setujui usulan
// menjadi custom rule yang langsung aktif di engine.
func (d *Dashboard) handleProposedApprove(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ruleMap, found, err := learner.Approve(d.store, pid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	rule, err := learner.ToRule(ruleMap)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.eng.AddCustomRules([]rules.Rule{rule})
	writeOK(w, map[string]any{"rule_id": rule.ID})
}

// handleProposedReject: POST /api/proposed/{id}/reject — tolak usulan.
func (d *Dashboard) handleProposedReject(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := learner.Reject(d.store, pid); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, nil)
}

// handleSiteUpsert: POST /api/sites — tambah/update site.
func (d *Dashboard) handleSiteUpsert(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if fieldStr(body, "domain", "") == "" {
		writeErr(w, http.StatusBadRequest, "domain wajib diisi")
		return
	}
	port := 8000
	if v, ok := body["upstream_port"]; ok {
		n, ok := toIntE(v)
		if !ok {
			writeErr(w, http.StatusBadRequest, "upstream_port harus angka")
			return
		}
		port = n
	}
	body["upstream_port"] = port
	sid, err := d.store.UpsertSite(body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.reloadSites()
	writeOK(w, map[string]any{"id": sid})
}

// handleSiteDelete: DELETE /api/sites/{id} — hapus site.
func (d *Dashboard) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.store.DeleteSite(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, nil)
}

// handleSiteToggle: POST /api/sites/{id}/toggle — nyalakan/matikan site.
func (d *Dashboard) handleSiteToggle(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	site["enabled"] = flipInt(site["enabled"])
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"enabled": pyBool(site["enabled"])})
}

// handleSiteDDoS: POST /api/sites/{id}/ddos — toggle Mode Serangan DDoS
// per-site; body opsional {enabled, ddos_rps}.
func (d *Dashboard) handleSiteDDoS(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	body, err := readJSON(r)
	if err != nil {
		body = map[string]any{}
	}
	if v, ok := body["enabled"]; ok {
		if pyBool(v) {
			site["ddos_mode"] = 1
		} else {
			site["ddos_mode"] = 0
		}
	} else {
		site["ddos_mode"] = flipInt(site["ddos_mode"])
	}
	if v, ok := body["ddos_rps"]; ok {
		if f, ok := toFloatE(v); ok && f >= 0.5 && f <= 1000 {
			site["ddos_rps"] = f
		}
	}
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.reloadSites()
	rps := 0.0
	if f, ok := toFloatE(site["ddos_rps"]); ok {
		rps = f
	}
	writeOK(w, map[string]any{
		"ddos_mode": pyBool(site["ddos_mode"]), "ddos_rps": rps,
	})
}

// reloadSites memuat ulang daftar site di proxy bila tersedia.
// Error diabaikan (proxy tetap pakai data lama) agar API dashboard
// tidak gagal hanya karena reload.
func (d *Dashboard) reloadSites() {
	if d.siteRel != nil {
		_ = d.siteRel.ReloadSites()
	}
}

// handleSiteGeoBlock: POST /api/sites/{id}/geoblock — atur daftar negara
// yang diblokir untuk site ini. Body: {"blocked_countries": ["CN","RU"]}
// atau {"blocked_countries": "CN, RU"}. Kosong -> ikut daftar global.
func (d *Dashboard) handleSiteGeoBlock(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var countries []string
	switch v := body["blocked_countries"].(type) {
	case string:
		countries = []string{}
		for _, c := range strings.Split(v, ",") {
			if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
				countries = append(countries, c)
			}
		}
	case []any:
		countries = []string{}
		for _, x := range v {
			if c, ok := x.(string); ok {
				if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
					countries = append(countries, c)
				}
			}
		}
	default:
		countries = []string{}
	}
	site["blocked_countries"] = countries
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.reloadSites()
	writeOK(w, map[string]any{"blocked_countries": countries})
}

// reloadProxyTLS me-reload sertifikat SNI di proxy. Return
// (tls_active, need_restart) seperti _reload_proxy_tls di Python.
func (d *Dashboard) reloadProxyTLS() (bool, bool) {
	if d.tls == nil {
		return false, true
	}
	if err := d.tls.ReloadTLS(); err != nil {
		return false, true
	}
	return true, false
}

// saveSiteCert memvalidasi lalu menyimpan cert/key site ke
// dataDir/certs/<id>/ (port save_site_cert dari tlscerts.py).
func saveSiteCert(dataDir, siteID, certPEM, keyPEM string) (string, string, error) {
	if err := tlscerts.ValidatePair(certPEM, keyPEM); err != nil {
		return "", "", err
	}
	dir := filepath.Join(dataDir, "certs", siteID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	withNL := func(s string) string {
		if strings.HasSuffix(s, "\n") {
			return s
		}
		return s + "\n"
	}
	if err := os.WriteFile(certPath, []byte(withNL(certPEM)), 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, []byte(withNL(keyPEM)), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// handleSiteCertUpload: POST /api/sites/{id}/cert — upload sertifikat TLS.
func (d *Dashboard) handleSiteCertUpload(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	certPEM := strings.TrimSpace(pyStr(body["cert_pem"]))
	keyPEM := strings.TrimSpace(pyStr(body["key_pem"]))
	if certPEM == "" || keyPEM == "" {
		writeErr(w, http.StatusBadRequest, "cert_pem & key_pem wajib diisi")
		return
	}
	certPath, keyPath, err := saveSiteCert(d.cfg.DataDir, pyStr(site["id"]),
		certPEM, keyPEM)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			writeErr(w, http.StatusInternalServerError,
				"gagal menyimpan: "+err.Error())
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	var expiresAt float64
	if t, err := tlscerts.ParseExpiry(certPEM); err == nil {
		expiresAt = float64(t.Unix())
	}
	domains := []string{}
	if ds, err := tlscerts.Domains(certPEM); err == nil && ds != nil {
		domains = ds
	}
	site["tls_cert"] = certPath
	site["tls_key"] = keyPath
	site["tls_expires_at"] = expiresAt
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tlsActive, needRestart := d.reloadProxyTLS()
	domain := pyStr(site["domain"])
	domainOK := len(domains) == 0
	for _, dm := range domains {
		if dm == domain {
			domainOK = true
			break
		}
		if strings.HasPrefix(dm, "*.") &&
			strings.HasSuffix(domain, dm[1:]) {
			domainOK = true
			break
		}
	}
	writeOK(w, map[string]any{
		"expires_at": expiresAt, "cert_domains": domains,
		"domain_match": domainOK, "tls_active": tlsActive,
		"need_restart": needRestart,
	})
}

// handleSiteCertDelete: DELETE /api/sites/{id}/cert — hapus sertifikat.
func (d *Dashboard) handleSiteCertDelete(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.RemoveAll(filepath.Join(d.cfg.DataDir, "certs", pyStr(site["id"])))
	site["tls_cert"] = ""
	site["tls_key"] = ""
	site["tls_expires_at"] = 0
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tlsActive, needRestart := d.reloadProxyTLS()
	writeOK(w, map[string]any{
		"tls_active": tlsActive, "need_restart": needRestart,
	})
}

// handleSiteRecaptcha: POST /api/sites/{id}/recaptcha — toggle reCAPTCHA
// per site.
func (d *Dashboard) handleSiteRecaptcha(w http.ResponseWriter, r *http.Request) {
	site, err := d.store.GetSite(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	body, err := readJSON(r)
	if err != nil {
		body = map[string]any{}
	}
	if v, ok := body["enabled"]; ok {
		if pyBool(v) {
			site["recaptcha_enabled"] = 1
		} else {
			site["recaptcha_enabled"] = 0
		}
	} else {
		site["recaptcha_enabled"] = flipInt(site["recaptcha_enabled"])
	}
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.reloadSites()
	writeOK(w, map[string]any{
		"recaptcha_enabled": pyBool(site["recaptcha_enabled"]),
	})
}

// handleRuleToggle: POST /api/rules/{id}/toggle — nyalakan/matikan signature
// global.
func (d *Dashboard) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	body, err := readJSON(r)
	if err != nil {
		body = map[string]any{}
	}
	var disabled bool
	if v, ok := body["disabled"]; ok {
		disabled = pyBool(v)
	} else {
		disabled = !d.isDisabled(ruleID)
	}
	if !d.setRuleDisabled(ruleID, disabled) {
		writeErr(w, http.StatusNotFound, "rule tidak ditemukan")
		return
	}
	writeOK(w, map[string]any{"disabled": disabled})
}

// handleCacheConfigPost: POST /api/cache/config — simpan konfigurasi cache
// per site.
func (d *Dashboard) handleCacheConfigPost(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	site, err := d.store.GetSite(pyStr(body["site_id"]))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pyBool(body["enabled"]) {
		site["cache_enabled"] = 1
	} else {
		site["cache_enabled"] = 0
	}
	clampInt := func(key, dbKey string, lo, hi, def int) {
		if v, ok := body[key]; ok {
			if n, ok := toIntE(v); ok {
				if n < lo {
					n = lo
				}
				if n > hi {
					n = hi
				}
				site[dbKey] = n
				return
			}
			site[dbKey] = def
		}
	}
	clampInt("ttl", "cache_ttl", 1, 86400, 60)
	clampInt("max_entries", "cache_max_entries", 10, 100000, 1000)
	clampInt("max_object_kb", "cache_max_object_kb", 1, 102400, 2048)
	if v, ok := body["bypass_cookies"]; ok {
		if list, ok := v.([]any); ok {
			cookies := make([]string, 0, len(list))
			for _, c := range list {
				cookies = append(cookies, pyStr(c))
			}
			site["cache_bypass_cookies"] = cookies
		} else {
			site["cache_bypass_cookies"] = []string{}
		}
	}
	if _, err := d.store.UpsertSite(site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, nil)
}

// handleCachePurge: POST /api/cache/purge — hapus cache per site / URL.
func (d *Dashboard) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	siteID := pyStr(body["site_id"])
	if siteID != "" {
		if _, err := d.store.GetSite(siteID); errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "site tidak ditemukan")
			return
		} else if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	n := d.cache.Purge(siteID, pyStr(body["url"]))
	writeOK(w, map[string]any{"purged": n})
}

// handleIPListAdd: POST /api/iplists — tambah entri whitelist/blacklist.
func (d *Dashboard) handleIPListAdd(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	network := strings.TrimSpace(pyStr(body["network"]))
	lst := strings.TrimSpace(pyStr(body["list"]))
	if network == "" || (lst != "white" && lst != "black") {
		writeErr(w, http.StatusBadRequest, "network & list=white|black wajib")
		return
	}
	normalized, ok := normalizeNetwork(network)
	if !ok {
		writeErr(w, http.StatusBadRequest, "format IP/CIDR tidak valid")
		return
	}
	eid, err := randomID12()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var expiresAt any
	if f, ok := toFloatE(body["expires_hours"]); ok && f > 0 {
		expiresAt = nowSec() + f*3600
	}
	scope := strings.TrimSpace(pyStr(body["scope"]))
	if scope == "" {
		scope = "global"
	}
	entry := map[string]any{
		"id": eid, "network": normalized, "list": lst, "scope": scope,
		"note": strings.TrimSpace(pyStr(body["note"])), "expires_at": expiresAt,
	}
	if err := d.store.UpsertIPEntry(entry); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.ipl.Invalidate()
	writeOK(w, map[string]any{"id": eid})
}

// handleIPListDelete: DELETE /api/iplists/{id} — hapus entri.
func (d *Dashboard) handleIPListDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.store.DeleteIPEntry(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.ipl.Invalidate()
	writeOK(w, nil)
}

// handleIPGroupCreate: POST /api/ip-groups — buat grup IP baru.
func (d *Dashboard) handleIPGroupCreate(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(pyStr(body["name"])) == "" {
		writeErr(w, http.StatusBadRequest, "nama grup wajib diisi")
		return
	}
	kind := pyStr(body["kind"])
	if kind == "" {
		kind = "black"
	}
	gid, err := d.store.CreateIPGroup(pyStr(body["name"]), kind,
		pyStr(body["description"]))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	d.ipl.Invalidate()
	writeOK(w, map[string]any{"id": gid})
}

// handleIPGroupUpdate: PUT /api/ip-groups/{id} — update nama/deskripsi grup.
func (d *Dashboard) handleIPGroupUpdate(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var nameP, descP *string
	if v, ok := body["name"]; ok {
		s := pyStr(v)
		nameP = &s
	}
	if v, ok := body["description"]; ok {
		s := pyStr(v)
		descP = &s
	}
	updated, err := d.store.UpdateIPGroup(r.PathValue("id"), nameP, descP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !updated {
		writeErr(w, http.StatusNotFound, "grup tidak ditemukan")
		return
	}
	d.ipl.Invalidate()
	writeOK(w, nil)
}

// handleIPGroupDelete: DELETE /api/ip-groups/{id} — hapus grup.
func (d *Dashboard) handleIPGroupDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.store.DeleteIPGroup(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.ipl.Invalidate()
	writeOK(w, nil)
}

// handleIPGroupAddMember: POST /api/ip-groups/{id}/members — tambah CIDR.
func (d *Dashboard) handleIPGroupAddMember(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(pyStr(body["cidr"])) == "" {
		writeErr(w, http.StatusBadRequest, "cidr wajib diisi")
		return
	}
	cidr, err := d.store.AddGroupMember(r.PathValue("id"), pyStr(body["cidr"]))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	d.ipl.Invalidate()
	writeOK(w, map[string]any{"cidr": cidr})
}

// handleIPGroupDelMember: DELETE /api/ip-groups/{id}/members — hapus anggota
// (cidr via query atau body).
func (d *Dashboard) handleIPGroupDelMember(w http.ResponseWriter, r *http.Request) {
	cidr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if cidr == "" {
		if body, err := readJSON(r); err == nil {
			cidr = strings.TrimSpace(pyStr(body["cidr"]))
		}
	}
	if cidr == "" {
		writeErr(w, http.StatusBadRequest, "cidr wajib diisi")
		return
	}
	if err := d.store.RemoveGroupMember(r.PathValue("id"), cidr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.ipl.Invalidate()
	writeOK(w, nil)
}

// handleRecaptchaPost: POST /api/recaptcha/config — simpan pengaturan
// reCAPTCHA global.
func (d *Dashboard) handleRecaptchaPost(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	mode := strings.TrimSpace(pyStr(body["mode"]))
	if mode == "" {
		mode = "v2"
	}
	if mode != "v2" && mode != "v3" {
		writeErr(w, http.StatusBadRequest, "mode harus v2 atau v3")
		return
	}
	var secretArg *string
	if v, ok := body["secret_key"]; ok {
		s := pyStr(v) // "" eksplisit = kosongkan
		secretArg = &s
	}
	cfgPath := d.cfg.ConfigPath
	if cfgPath == "" {
		cfgPath = "config.yaml"
	}
	enabled := pyBool(body["enabled"])
	siteKey := strings.TrimSpace(pyStr(body["site_key"]))
	if err := config.SaveRecaptchaConfig(cfgPath, enabled, siteKey,
		secretArg, mode); err != nil {
		writeErr(w, http.StatusInternalServerError,
			"gagal menyimpan: "+err.Error())
		return
	}
	// Muat ulang ke objek config yang dipakai pipeline (berlaku langsung).
	rc := &d.cfg.Recaptcha
	rc.Enabled = enabled
	rc.SiteKey = siteKey
	if secretArg != nil {
		rc.SecretKey = *secretArg
	}
	rc.Mode = mode
	writeOK(w, nil)
}

// handleCFConfigPost: POST /api/cf/config — simpan token + mapping zone.
func (d *Dashboard) handleCFConfigPost(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if v, ok := body["api_token"]; ok {
		token := pyStr(v)
		cfgPath := d.cfg.ConfigPath
		if cfgPath == "" {
			cfgPath = "config.yaml"
		}
		if err := config.SaveCFConfig(cfgPath, &token); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.cfg.Cloudflare.APIToken = token
	}
	if zones, ok := body["zones"].([]any); ok {
		for _, z := range zones {
			zm, ok := z.(map[string]any)
			if !ok {
				continue
			}
			site, err := d.store.GetSite(pyStr(zm["site_id"]))
			if err != nil {
				continue
			}
			site["cf_zone_id"] = strings.TrimSpace(pyStr(zm["zone_id"]))
			_, _ = d.store.UpsertSite(site)
		}
	}
	writeOK(w, map[string]any{
		"api_token_set": d.cfg.Cloudflare.APIToken != "",
	})
}

// handleCFPurge: POST /api/cf/purge — purge cache Cloudflare per zone.
func (d *Dashboard) handleCFPurge(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	site, err := d.store.GetSite(pyStr(body["site_id"]))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var urls []string
	if v, ok := body["urls"]; ok && v != nil {
		arr, ok := v.([]any)
		if !ok {
			writeErr(w, http.StatusBadRequest, "urls harus list")
			return
		}
		for _, u := range arr {
			urls = append(urls, pyStr(u))
		}
	}
	token := d.cfg.Cloudflare.APIToken
	zoneID := pyStr(site["cf_zone_id"])
	var perr error
	if len(urls) > 0 {
		perr = cloudflare.PurgeFiles(token, zoneID, urls)
	} else {
		perr = cloudflare.PurgeCache(token, zoneID)
	}
	if perr != nil {
		writeErr(w, http.StatusBadGateway, perr.Error())
		return
	}
	writeOK(w, nil)
}
