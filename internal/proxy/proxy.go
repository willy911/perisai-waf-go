// Package proxy adalah reverse proxy HTTP(S) Perisai WAF: menggabungkan
// seluruh lapisan pertahanan (routing site, iplists, reputasi, rate limit,
// Mode Serangan DDoS, scan upload, rules engine, AI agent, challenge,
// cache WAF-side) menjadi satu pipeline per request, lalu meneruskan
// request bersih ke upstream.
//
// Merupakan port dari perisai/proxy.py + perisai/waf.py (Python).
// Urutan pipeline disamakan persis dengan PerisaiWAF.handle Python.
package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/cache"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/iplists"
	"github.com/willy911/perisai-waf/internal/learner"
	"github.com/willy911/perisai-waf/internal/ratelimit"
	"github.com/willy911/perisai-waf/internal/recaptcha"
	"github.com/willy911/perisai-waf/internal/reputation"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
	"github.com/willy911/perisai-waf/internal/uploadscan"
)

const (
	// CookieName adalah nama cookie challenge JS.
	//
	// PENYIMPANGAN dari Python: perisai/actions.py memakai "perisai_ch",
	// sedangkan kontrak port ini (dan BUILD_PLAN) menetapkan
	// "perisai_chal". Token antar implementasi tidak saling terbaca.
	CookieName = "perisai_chal"
	// ChallengeTTL adalah masa berlaku token challenge, dalam detik.
	ChallengeTTL = 3600
	// RecaptchaVerifyPath adalah endpoint internal verifikasi reCAPTCHA.
	// Request ke path ini tidak diteruskan ke upstream (sama spt Python).
	RecaptchaVerifyPath = "/__perisai__/recaptcha-verify"
)

// hopByHop adalah header yang tidak diteruskan ke/diambil dari upstream.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Connection",
}

// statusCacheable adalah status respons upstream yg boleh disimpan di cache
// WAF-side (sama seperti CACHEABLE_STATUS Python).
var statusCacheable = map[int]bool{200: true, 301: true, 302: true}

// -- token challenge (port perisai/actions.py) -------------------------------

// challengeSig menghitung HMAC-SHA256(secret, "ip.expiry") dalam hex.
func challengeSig(secret, ip string, expiry int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s.%d", ip, expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

// issueChallengeToken membuat token "expiry.hexhmac" — port persis
// actions.issue_challenge_token.
func issueChallengeToken(secret, ip string) string {
	expiry := time.Now().Unix() + ChallengeTTL
	return fmt.Sprintf("%d.%s", expiry, challengeSig(secret, ip, expiry))
}

// verifyChallengeToken memvalidasi token challenge — port persis
// actions.verify_challenge_token.
func verifyChallengeToken(secret, ip, token string) bool {
	if token == "" {
		return false
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if expiry < time.Now().Unix() {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(challengeSig(secret, ip, expiry)))
}

// challengeCookie mengambil nilai cookie challenge dari request.
func challengeCookie(r *http.Request) string {
	for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
		k, v, found := strings.Cut(part, "=")
		if found && strings.TrimSpace(k) == CookieName {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// -- halaman HTML (port perisai/actions.py) -----------------------------------

const pageCSS = `
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;
max-width:480px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.shield{font-size:56px}.title{font-size:22px;font-weight:700;margin:12px 0 8px}
.desc{color:#94a3b8;font-size:14px;line-height:1.6}.ref{margin-top:16px;font-size:12px;color:#64748b}
a.btn{display:inline-block;margin-top:20px;background:#6366f1;color:#fff;text-decoration:none;
padding:10px 24px;border-radius:8px;font-weight:600}
`

// htmlPage membangun kerangka halaman Perisai. title/ref di-escape;
// desc/extra dianggap HTML tepercaya dari kode sendiri.
func htmlPage(title, desc, ref, extra string) []byte {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>` + html.EscapeString(title) + ` — Perisai WAF</title><style>`)
	b.WriteString(pageCSS)
	b.WriteString(`</style></head><body><div class="card"><div class="shield">🛡️</div>`)
	b.WriteString(`<div class="title">` + html.EscapeString(title) + `</div>`)
	b.WriteString(`<div class="desc">` + desc + `</div>`)
	b.WriteString(extra)
	b.WriteString(`<div class="ref">Perisai WAF &middot; ref: ` +
		html.EscapeString(ref) + `</div></div></body></html>`)
	return []byte(b.String())
}

// blockPage adalah halaman 403 — port actions.block_page.
func blockPage(requestID, reason string) []byte {
	return htmlPage("Akses Ditolak 🛡️",
		"Permintaan Anda terdeteksi sebagai serangan dan diblokir. Alasan: "+
			html.EscapeString(reason)+
			" Jika ini kesalahan, hubungi administrator website.",
		requestID, "")
}

// rateLimitedPage adalah halaman 429 — port actions.rate_limited_page.
func rateLimitedPage() []byte {
	return htmlPage("Terlalu Banyak Permintaan 🛡️",
		"Anda mengirim terlalu banyak request dalam waktu singkat. "+
			"Tunggu sebentar lalu coba lagi.",
		"rate-limit", "")
}

// recaptchaPage adalah halaman challenge reCAPTCHA — port
// actions.recaptcha_page. Token diverifikasi server-side via
// POST /__perisai__/recaptcha-verify.
func recaptchaPage(siteKey, mode string) []byte {
	sk := html.EscapeString(siteKey)
	var widget string
	if mode == "v3" {
		widget = `<script src="https://www.google.com/recaptcha/api.js?render=` + sk + `"></script>
<script>
grecaptcha.ready(function(){
  grecaptcha.execute("` + sk + `", {action:"challenge"}).then(onRecaptcha);
});
</script><div class="desc" style="margin-top:16px">Memverifikasi Anda bukan robot…</div>`
	} else {
		widget = `<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<div class="g-recaptcha" data-sitekey="` + sk + `" data-callback="onRecaptcha"
     style="display:inline-block;margin-top:12px"></div>`
	}
	extra := widget + `<div class="desc" id="rcMsg" style="margin-top:12px"></div>
<script>
function onRecaptcha(token){
  document.getElementById("rcMsg").textContent = "Memverifikasi…";
  fetch("` + RecaptchaVerifyPath + `", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({token: token})
  }).then(r => r.json()).then(d => {
    if(d.ok){ location.reload(); }
    else { document.getElementById("rcMsg").textContent = "❌ " + (d.error || "gagal"); }
  }).catch(() => {
    document.getElementById("rcMsg").textContent = "❌ Gangguan jaringan.";
  });
}
</script>`
	return htmlPage("Verifikasi Keamanan 🛡️",
		"Trafik Anda terlihat tidak biasa. "+
			"Selesaikan verifikasi berikut untuk melanjutkan.",
		"recaptcha", extra)
}

// -- Server ------------------------------------------------------------------

// ddosLimiter adalah rate limiter ketat per-site untuk Mode Serangan DDoS.
type ddosLimiter struct {
	lim *ratelimit.Limiter
	rps float64
}

// Server adalah reverse proxy WAF. Aman dipakai dari banyak goroutine:
// seluruh state bersama dikunci mutex.
type Server struct {
	cfg   *config.WAFConfig
	eng   *rules.Engine
	orch  *agent.Orchestrator
	store *storage.Storage

	limiter *ratelimit.Limiter
	rep     *reputation.Reputation
	lists   *iplists.IPLists
	pcache  *cache.Cache

	secret  string
	trusted []netip.Prefix

	mu       sync.RWMutex
	sites    map[string]*config.Site // domain (lowercase) -> site
	order    []string                // domain terurut, utk fallback deterministik
	byID     map[string]*config.Site
	disabled map[string]bool // signature yg dimatikan secara global

	ddosMu sync.Mutex
	ddos   map[string]*ddosLimiter

	certMu      sync.Mutex
	certCache   map[string]*tls.Certificate
	defaultCert *tls.Certificate
}

// NewServer membuat Server. Parameter extra (variadic, opsional) boleh berisi
// *ratelimit.Limiter, *reputation.Reputation, *iplists.IPLists, dan/atau
// *cache.Cache; yang tidak diberikan dibuat dari cfg.
func NewServer(cfg *config.WAFConfig, eng *rules.Engine, orch *agent.Orchestrator,
	store *storage.Storage, extra ...any) *Server {
	s := &Server{
		cfg: cfg, eng: eng, orch: orch, store: store,
		sites:     map[string]*config.Site{},
		byID:      map[string]*config.Site{},
		disabled:  map[string]bool{},
		ddos:      map[string]*ddosLimiter{},
		certCache: map[string]*tls.Certificate{},
	}
	s.secret = cfg.Dashboard.Token
	if s.secret == "" {
		s.secret = "perisai-default-secret"
	}
	for _, e := range extra {
		switch v := e.(type) {
		case *ratelimit.Limiter:
			s.limiter = v
		case *reputation.Reputation:
			s.rep = v
		case *iplists.IPLists:
			s.lists = v
		case *cache.Cache:
			s.pcache = v
		}
	}
	if s.limiter == nil {
		s.limiter = ratelimit.New(cfg.RateLimit.RPS, cfg.RateLimit.Burst)
	}
	if s.rep == nil {
		s.rep = reputation.New(cfg.Reputation, store)
	}
	if s.lists == nil {
		s.lists = iplists.New(store)
	}
	if s.pcache == nil {
		s.pcache = cache.New()
	}
	for _, c := range cfg.Server.TrustedProxies {
		if p, ok := parseTrustedCIDR(c); ok {
			s.trusted = append(s.trusted, p)
		}
	}
	// Sertifikat default (bila TLS diaktifkan dan file ada).
	if cfg.TLS.Enabled && cfg.TLS.Cert != "" {
		if cert, err := tls.LoadX509KeyPair(
			cfg.AbsPath(cfg.TLS.Cert), cfg.AbsPath(cfg.TLS.Key)); err == nil {
			s.defaultCert = &cert
		}
	}
	_ = s.ReloadSites()
	s.loadGlobalDisabled()
	return s
}

// Handler mengembalikan http.Handler untuk server ini.
func (s *Server) Handler() http.Handler { return s }

// -- situs -------------------------------------------------------------------

// ReloadSites memuat ulang daftar situs dari DB (dipanggil setelah CRUD
// dashboard) — port PerisaiWAF.reload_sites.
func (s *Server) ReloadSites() error {
	rows, err := s.store.ListSites()
	if err != nil {
		return err
	}
	byDomain := make(map[string]*config.Site, len(rows))
	byID := make(map[string]*config.Site, len(rows))
	for _, d := range rows {
		st := siteFromMap(d)
		byDomain[strings.ToLower(st.Domain)] = st
		byID[st.ID] = st
	}
	order := make([]string, 0, len(byDomain))
	for d := range byDomain {
		order = append(order, d)
	}
	sort.Strings(order)
	s.mu.Lock()
	s.sites, s.order, s.byID = byDomain, order, byID
	s.mu.Unlock()
	return nil
}

// route menentukan site dari Host header. Bila sites dikonfigurasi tapi host
// tidak cocok, jatuh kembali ke site pertama yang enabled.
//
// PENYIMPANGAN dari Python: PerisaiWAF.handle membalas 404
// "Domain Tidak Dilindungi" untuk host tak dikenal; kontrak port ini
// meminta fallback ke site default/pertama.
func (s *Server) route(host string) *config.Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.sites) == 0 {
		return nil
	}
	if st, ok := s.sites[strings.ToLower(host)]; ok && st.Enabled {
		return st
	}
	for _, d := range s.order {
		if st := s.sites[d]; st.Enabled {
			return st
		}
	}
	return nil
}

// -- disabled rules ----------------------------------------------------------

// loadGlobalDisabled memuat signature yg dimatikan secara global dari
// settings (port PerisaiWAF._load_global_disabled).
func (s *Server) loadGlobalDisabled() {
	raw, err := s.store.GetSetting("disabled_rules", "[]")
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal([]byte(raw), &ids) != nil {
		return
	}
	s.mu.Lock()
	for _, id := range ids {
		s.disabled[id] = true
	}
	s.mu.Unlock()
}

// SetRuleDisabled menyalakan/mematikan signature secara global (persisten di
// settings). False bila rule id tak dikenal — port
// PerisaiWAF.set_rule_disabled.
func (s *Server) SetRuleDisabled(ruleID string, disabled bool) bool {
	found := false
	for _, r := range s.eng.Rules() {
		if r.ID == ruleID {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	s.mu.Lock()
	if disabled {
		s.disabled[ruleID] = true
	} else {
		delete(s.disabled, ruleID)
	}
	ids := make([]string, 0, len(s.disabled))
	for id := range s.disabled {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	sort.Strings(ids)
	data, _ := json.Marshal(ids)
	_ = s.store.SetSetting("disabled_rules", string(data))
	return true
}

// GlobalDisabledRules mengembalikan daftar signature global yg dimatikan.
func (s *Server) GlobalDisabledRules() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.disabled))
	for id := range s.disabled {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// disabledFor menggabungkan disabled_rules per-site dengan global.
func (s *Server) disabledFor(site *config.Site) map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.disabled) == 0 && (site == nil || len(site.DisabledRules) == 0) {
		return nil
	}
	out := make(map[string]bool, len(s.disabled)+8)
	for id := range s.disabled {
		out[id] = true
	}
	if site != nil {
		for _, id := range site.DisabledRules {
			out[id] = true
		}
	}
	return out
}

// filterDisabled membuang hit yang rule ID-nya dimatikan (per-site/global),
// menghitung ulang Score = jumlah bobot (cap 100), menentukan ulang Action
// dari thresholds, dan menyaring Reasons yang merujuk rule disabled.
//
// Diperlukan karena rules.Engine.Triage (Go) tidak punya parameter
// disabled_ids seperti Engine.triage Python.
func filterDisabled(req *rules.Request, t rules.TriageResult,
	disabled map[string]bool, th config.Thresholds) rules.TriageResult {
	if len(disabled) == 0 {
		return t
	}
	hits := make([]rules.Hit, 0, len(t.Hits))
	for _, h := range t.Hits {
		if !disabled[h.RuleID] {
			hits = append(hits, h)
		}
	}
	reasons := make([]string, 0, len(t.Reasons))
	for _, rs := range t.Reasons {
		bad := false
		for id := range disabled {
			if strings.Contains(rs, id) {
				bad = true
				break
			}
		}
		if !bad {
			reasons = append(reasons, rs)
		}
	}
	// Hitung ulang skor dari bobot hit tersisa + anomali struktural
	// (disamakan dengan rules.Engine).
	score := 0.0
	for _, h := range hits {
		score += h.Weight
	}
	if utf8.RuneCountInString(req.Query) > 2000 {
		score += 10
	}
	if strings.Count(req.Query, "&") > 50 {
		score += 10
	}
	if !isCommonMethod(strings.ToUpper(req.Method)) {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	action := "allow"
	switch {
	case score >= th.BlockScore:
		action = "block"
	case score >= th.AgentScore:
		action = "agent"
	}
	return rules.TriageResult{
		Score: score, Action: action, Hits: hits, Reasons: reasons,
	}
}

func isCommonMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// -- pipeline utama ----------------------------------------------------------

// ServeHTTP menjalankan pipeline WAF per request, dengan urutan persis
// PerisaiWAF.handle Python: site -> iplists -> reputasi -> cookie challenge
// -> ddos_mode -> rate limit -> body/upload scan -> triase -> cache ->
// agent -> proxy upstream.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	ts := float64(t0.UnixNano()) / 1e9
	reqID := newRequestID()

	// Baca body lebih dulu (batas max_body_mb), seperti proxy.py.
	maxBody := int64(s.cfg.Server.MaxBodyMB) * 1024 * 1024
	if maxBody <= 0 {
		maxBody = 10 * 1024 * 1024
	}
	if r.ContentLength > maxBody {
		s.writeDirect(w, 413, []byte("Payload terlalu besar"),
			"text/plain; charset=utf-8", nil)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	r.Body.Close()
	if err != nil || int64(len(body)) > maxBody {
		s.writeDirect(w, 413, []byte("Payload terlalu besar"),
			"text/plain; charset=utf-8", nil)
		return
	}

	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := r.URL.RawQuery
	clientIP := s.clientIP(r)

	// Endpoint internal: verifikasi reCAPTCHA (jangan diteruskan ke upstream).
	if path == RecaptchaVerifyPath {
		if r.Method != http.MethodPost {
			s.writeDirect(w, 405, []byte("method tidak diizinkan"),
				"text/plain; charset=utf-8", nil)
			return
		}
		s.handleRecaptchaVerify(w, body, clientIP)
		return
	}

	host := hostOnly(r.Host)
	site := s.route(host)
	siteID := ""
	if site != nil {
		siteID = site.ID
	}

	// Di Go, Host tidak ada di r.Header (melainkan r.Host); Python
	// menyertakannya di dict headers — samakan agar engine memindai dan
	// cache key konsisten.
	flatHeaders := flattenHeaders(r.Header)
	flatHeaders["host"] = r.Host
	req := &rules.Request{
		ID:       reqID,
		Method:   strings.ToUpper(r.Method),
		Path:     path,
		Query:    query,
		Headers:  flatHeaders,
		Body:     body,
		ClientIP: clientIP,
	}
	decision, agentConf := "allow", 0.0
	logReq := func(dec, topRule string, score, aconf float64) {
		dur := math.Round(time.Since(t0).Seconds()*10000) / 10
		_ = s.store.LogRequest(req.ID, ts, req.ClientIP, req.Method, req.Path,
			req.Query, score, dec, aconf, dur, topRule, siteID)
	}

	// -0. IP whitelist/blacklist manual (whitelist bypass semua)
	switch s.lists.Check(clientIP, siteID) {
	case "white":
		logReq("allow", "WHITELIST", 0, 0)
		s.forward(w, r, req, site, body)
		return
	case "black":
		logReq("block", "BLACKLIST", 100, 0)
		s.writeDirect(w, 403, blockPage(reqID, "IP masuk daftar hitam manual."),
			"text/html; charset=utf-8", nil)
		return
	}

	// 0. Reputasi IP (blokir sementara dari riwayat)
	if s.rep.Check(clientIP) {
		logReq("block", "REPUTATION", 100, 0)
		s.writeDirect(w, 403,
			blockPage(reqID, "IP diblokir sementara karena riwayat serangan."),
			"text/html; charset=utf-8", nil)
		return
	}

	cookieOK := verifyChallengeToken(s.secret, clientIP, challengeCookie(r))

	// 0b. Mode Serangan DDoS per-site: challenge-first untuk pengunjung
	//     baru + rate limit ketat. Whitelist sudah bypass di atas.
	if site != nil && site.DDoSMode {
		if !cookieOK {
			logReq("challenge", "DDOS-MODE", 0, 0)
			s.issueChallenge(w, r, clientIP)
			return
		}
		if !s.ddosAllow(site, clientIP) {
			logReq("rate_limited", "DDOS-LIMIT", 0, 0)
			s.writeDirect(w, 429, rateLimitedPage(),
				"text/html; charset=utf-8", nil)
			return
		}
	}

	// 1. Rate limit global
	if s.cfg.RateLimit.Enabled && !s.limiter.Allow(clientIP) {
		logReq("rate_limited", "RATE-LIMIT", 0, 0)
		s.writeDirect(w, 429, rateLimitedPage(),
			"text/html; charset=utf-8", nil)
		return
	}

	// 1b. Scan file upload (multipart) sebelum diteruskan
	if s.shouldScanUpload(req) {
		if fname, reason, blocked := s.scanUploads(req); blocked {
			s.rep.RecordBlock(clientIP)
			logReq("block", "MALWARE-UPLOAD", 100, 0)
			s.writeDirect(w, 403, blockPage(reqID,
				"upload berbahaya ditolak ("+fname+": "+reason+")"),
				"text/html; charset=utf-8", nil)
			return
		}
	}

	// 2. Triase rules engine (dengan rule yang dimatikan per-site/global)
	triage := filterDisabled(req, s.eng.Triage(req),
		s.disabledFor(site), s.cfg.Thresholds)
	score := triage.Score
	topRule := ""
	if len(triage.Hits) > 0 {
		topRule = triage.Hits[0].RuleID
	}
	if triage.Action == "block" {
		s.rep.RecordBlock(clientIP)
		logReq("block", topRule, score, 0)
		s.writeDirect(w, 403,
			blockPage(reqID, "terdeteksi pola serangan ("+topRule+")"),
			"text/html; charset=utf-8", nil)
		return
	}

	// 2b. Cache WAF-side: sajikan dari cache untuk request bersih.
	//     Serangan & trafik abu-abu tetap lewat pipeline penuh.
	if triage.Action == "allow" && site != nil && site.CacheEnabled {
		if entry, ok := s.cacheLookup(site, req); ok {
			logReq("cache_hit", topRule, score, 0)
			s.serveCacheHit(w, entry)
			return
		}
	}

	// 3. Zona abu-abu -> AI agent (dilewati bila sudah lolos challenge /
	//    agent dimatikan untuk site ini)
	if triage.Action == "agent" && !cookieOK {
		if site != nil && !site.AgentEnabled {
			decision = "allow" // agent dimatikan untuk site ini
		} else if verdict, verr := s.orch.Analyze(req, triage); verr == nil {
			agentConf = verdict.Confidence
			if len(verdict.SuggestedRule) > 0 {
				s.maybeLearn(verdict, triage)
			}
			switch verdict.Decision {
			case "block":
				s.rep.RecordBlock(clientIP)
				logReq("block", topRule, score, agentConf)
				s.writeDirect(w, 403,
					blockPage(reqID, "AI agent mengkonfirmasi serangan"),
					"text/html; charset=utf-8", nil)
				return
			case "challenge":
				logReq("challenge", topRule, score, agentConf)
				if s.useRecaptcha(site) {
					s.writeDirect(w, 200,
						recaptchaPage(s.cfg.Recaptcha.SiteKey, s.cfg.Recaptcha.Mode),
						"text/html; charset=utf-8", nil)
				} else {
					s.issueChallenge(w, r, clientIP)
				}
				return
			default:
				decision = "allow"
			}
		} else {
			// PENYIMPANGAN dari Python: orchestrator gagal total (mis.
			// DB audit down) -> fail-open agar layanan tetap jalan.
			// Python melempar 500 di titik ini.
			decision = "allow"
		}
	}

	logReq(decision, topRule, score, agentConf)
	s.forward(w, r, req, site, body)
}

// clientIP menentukan IP pengunjung asli. Bila koneksi datang dari
// proxy/CDN terpercaya (trusted_proxies), ambil dari header
// CF-Connecting-IP lalu X-Forwarded-For. Selain itu peer IP dipakai
// langsung (anti-spoof) — port _client_ip proxy.py.
func (s *Server) clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(peer); err == nil {
		peer = h
	}
	if len(s.trusted) == 0 {
		return peer
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return peer
	}
	trusted := false
	for _, n := range s.trusted {
		if n.Contains(addr) {
			trusted = true
			break
		}
	}
	if !trusted {
		return peer
	}
	for _, hdr := range []string{"CF-Connecting-IP", "X-Forwarded-For"} {
		val := r.Header.Get(hdr)
		if val == "" {
			continue
		}
		cand := strings.TrimSpace(strings.SplitN(val, ",", 2)[0])
		if _, err := netip.ParseAddr(cand); err == nil {
			return cand
		}
	}
	return peer
}

// ddosAllow menerapkan rate limiter ketat per-site untuk Mode Serangan
// (dibuat lazy; dibuat ulang bila ddos_rps berubah) — port
// PerisaiWAF._ddos_limiter.
func (s *Server) ddosAllow(site *config.Site, ip string) bool {
	rps := site.DDoSRPS
	if rps < 0.5 {
		rps = 0.5
	}
	s.ddosMu.Lock()
	defer s.ddosMu.Unlock()
	dl, ok := s.ddos[site.ID]
	if !ok || dl.rps != rps {
		dl = &ddosLimiter{
			lim: ratelimit.New(rps, max(1, int(rps*2))),
			rps: rps,
		}
		s.ddos[site.ID] = dl
	}
	return dl.lim.Allow(ip)
}

// useRecaptcha melaporkan apakah challenge untuk site ini memakai reCAPTCHA.
func (s *Server) useRecaptcha(site *config.Site) bool {
	rc := s.cfg.Recaptcha
	return site != nil && site.RecaptchaEnabled &&
		rc.Enabled && rc.SiteKey != "" && rc.SecretKey != ""
}

// issueChallenge menerbitkan token challenge baru sebagai cookie lalu
// mengarahkan browser kembali ke URL yang sama.
//
// PENYIMPANGAN dari Python: actions.challenge_page membalas 200 + HTML
// yang menyetel cookie via document.cookie (butuh JavaScript) lalu reload
// otomatis. Versi Go memakai 302 + Set-Cookie server-side: bekerja tanpa
// JavaScript dan bisa diuji tanpa browser.
func (s *Server) issueChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	token := issueChallengeToken(s.secret, ip)
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/",
		MaxAge: ChallengeTTL, SameSite: http.SameSiteLaxMode,
	})
	loc := r.URL.RequestURI()
	if loc == "" {
		loc = "/"
	}
	w.Header().Set("Location", loc)
	s.writeDirect(w, http.StatusFound,
		[]byte(`<html><body>Verifikasi keamanan… <a href="`+
			html.EscapeString(loc)+`">lanjutkan</a></body></html>`),
		"text/html; charset=utf-8", nil)
}

// handleRecaptchaVerify memverifikasi token widget reCAPTCHA ke Google,
// lalu menerbitkan cookie challenge — port
// ProxyHandler._recaptcha_verify.
func (s *Server) handleRecaptchaVerify(w http.ResponseWriter, body []byte, ip string) {
	var payload struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &payload)
	ok, verr := recaptcha.Verify(s.cfg.Recaptcha.SecretKey, payload.Token, ip, 0)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !ok {
		msg := "verifikasi gagal"
		if verr != nil {
			msg = verr.Error()
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error": msg,
		})
		return
	}
	token := issueChallengeToken(s.secret, ip)
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/",
		MaxAge: ChallengeTTL, SameSite: http.SameSiteLaxMode,
	})
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// writeDirect menulis respons langsung (block/challenge/429/dll).
func (s *Server) writeDirect(w http.ResponseWriter, status int, body []byte,
	contentType string, extra map[string]string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("X-Perisai", "1")
	for k, v := range extra {
		h.Set(k, v)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body) // net/http membuang body utk HEAD scr otomatis
}

// -- upload scan -------------------------------------------------------------

// shouldScanUpload memutuskan apakah request perlu dipindai file-nya —
// port UploadScanner.should_scan.
func (s *Server) shouldScanUpload(req *rules.Request) bool {
	if !s.cfg.Uploads.Enabled {
		return false
	}
	switch req.Method {
	case "POST", "PUT", "PATCH":
	default:
		return false
	}
	return strings.Contains(strings.ToLower(req.Headers["content-type"]),
		"multipart/form-data")
}

// scanUploads memindai tiap file di body multipart. Mengembalikan
// (nama_file, alasan, true) untuk file pertama yang diblokir —
// port UploadScanner.scan.
func (s *Server) scanUploads(req *rules.Request) (string, string, bool) {
	_, params, err := mime.ParseMediaType(req.Headers["content-type"])
	if err != nil || params["boundary"] == "" {
		return "", "", false
	}
	mr := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		name := part.FileName()
		if name == "" {
			continue // field biasa, bukan file
		}
		data, err := io.ReadAll(part)
		if err != nil {
			continue
		}
		if blocked, reason := uploadscan.Scan(name, data, s.cfg.Uploads); blocked {
			return name, reason, true
		}
	}
	return "", "", false
}

// maybeLearn mengusulkan signature baru dari verdict agent via package
// learner (port penuh Learner.learn_from_verdict).
func (s *Server) maybeLearn(v agent.Verdict, t rules.TriageResult) {
	learner.MaybeLearn(s.store, s.cfg.Learning, v, t)
}

// -- cache WAF-side ----------------------------------------------------------

// cacheLookup mencari respons di cache untuk request bersih — port
// PageCache.lookup.
func (s *Server) cacheLookup(site *config.Site, req *rules.Request) (cache.Entry, bool) {
	if !site.CacheEnabled || strings.ToUpper(req.Method) != "GET" {
		return cache.Entry{}, false
	}
	if req.Headers["authorization"] != "" {
		return cache.Entry{}, false
	}
	if s.pcache.BypassedByCookies(site, req.Headers["cookie"]) {
		return cache.Entry{}, false
	}
	key := cache.MakeKey(site.ID, req.Method,
		strings.ToLower(hostOnly(req.Headers["host"])), req.Path, req.Query)
	return s.pcache.Get(site.ID, key)
}

// serveCacheHit menyajikan respons dari cache (X-Perisai-Cache: HIT).
func (s *Server) serveCacheHit(w http.ResponseWriter, e cache.Entry) {
	h := w.Header()
	for k, vv := range e.Header {
		for _, v := range vv {
			h.Add(k, v)
		}
	}
	ct := e.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(e.Body)))
	h.Set("X-Perisai-Cache", "HIT")
	h.Set("X-Perisai", "1")
	w.WriteHeader(e.Status)
	_, _ = w.Write(e.Body)
}

// cacheStore menyimpan respons upstream ke cache bila memenuhi syarat —
// port PageCache.store. Mengembalikan true bila tersimpan.
func (s *Server) cacheStore(site *config.Site, req *rules.Request, host string,
	status int, hdr http.Header, data []byte) bool {
	if strings.ToUpper(req.Method) != "GET" {
		return false
	}
	if !statusCacheable[status] {
		return false
	}
	if req.Headers["authorization"] != "" {
		return false
	}
	if s.pcache.BypassedByCookies(site, req.Headers["cookie"]) {
		return false
	}
	keep := http.Header{}
	for k, vv := range hdr {
		switch strings.ToLower(k) {
		case "content-length", "x-perisai-cache", "connection":
			continue
		}
		keep[k] = vv
	}
	key := cache.MakeKey(site.ID, req.Method, strings.ToLower(host),
		req.Path, req.Query)
	return s.pcache.PutForSite(site, key, cache.Entry{
		Body:        data,
		Header:      keep,
		ContentType: hdr.Get("Content-Type"),
		Status:      status,
	})
}

// -- reverse proxy -----------------------------------------------------------

// forward meneruskan request bersih ke upstream via httputil.ReverseProxy —
// port ProxyHandler._forward.
func (s *Server) forward(w http.ResponseWriter, r *http.Request,
	req *rules.Request, site *config.Site, body []byte) {
	upHost, upPort := s.cfg.Server.UpstreamHost, s.cfg.Server.UpstreamPort
	useTLS := s.cfg.Server.UpstreamTLS
	verifyTLS := s.cfg.Server.UpstreamTLSVerify
	preserveHost := true
	if site != nil {
		upHost, upPort = site.UpstreamHost, site.UpstreamPort
		useTLS = site.UpstreamTLS
		verifyTLS = site.UpstreamTLSVerify
		preserveHost = site.PreserveHost
	}
	if upHost == "" {
		upHost = "127.0.0.1"
	}
	if upPort <= 0 {
		upPort = 80
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	targetHost := net.JoinHostPort(upHost, strconv.Itoa(upPort))

	timeout := s.cfg.Server.RequestTimeout
	if timeout <= 0 {
		timeout = 15
	}

	// Kembalikan body yang sudah dibaca agar ReverseProxy bisa meneruskannya.
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.ContentLength = int64(len(body))

	origHost := hostOnly(r.Host)

	proxy := &httputil.ReverseProxy{
		// Rewrite (bukan Director): dengan Director, ReverseProxy otomatis
		// me-append IP peer ke X-Forwarded-For setelah Director berjalan;
		// dengan Rewrite tidak — sehingga Set di bawah MENGGANTI header
		// persis seperti Python (bukan append).
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			out.URL.Scheme = scheme
			out.URL.Host = targetHost
			// Path & RawQuery dipertahankan dari request asli.
			// Teruskan Host asli domain ke upstream (penting untuk
			// vhost/shared hosting). Fallback ke host:port upstream
			// bila dimatikan — port _forward Python.
			if preserveHost && origHost != "" {
				out.Host = origHost
			} else {
				out.Host = targetHost
			}
			out.Header.Set("X-Forwarded-For", req.ClientIP)
			xfh := origHost
			if xfh == "" {
				xfh = pr.In.Host
			}
			out.Header.Set("X-Forwarded-Host", xfh)
			if pr.In.TLS != nil {
				out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				out.Header.Set("X-Forwarded-Proto", "http")
			}
			out.Header.Set("X-Perisai", "1")
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: time.Duration(timeout) * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !verifyTLS, //nolint:gosec // opsi upstream_tls_verify
			},
		},
		ModifyResponse: func(resp *http.Response) error {
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(data))
			resp.ContentLength = int64(len(data))
			for _, h := range hopByHop {
				resp.Header.Del(h)
			}
			// Simpan ke cache WAF-side bila memenuhi syarat.
			if site != nil && site.CacheEnabled {
				if s.cacheStore(site, req, origHost, resp.StatusCode,
					resp.Header, data) {
					resp.Header.Set("X-Perisai-Cache", "MISS")
				} else {
					resp.Header.Set("X-Perisai-Cache", "BYPASS")
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.writeDirect(w, http.StatusBadGateway,
				[]byte("Upstream tidak terjangkau: "+err.Error()),
				"text/plain; charset=utf-8", nil)
		},
	}
	proxy.ServeHTTP(w, r)
}

// -- TLS / ListenAndServe ----------------------------------------------------

// tlsActive melaporkan apakah listener harus TLS: aktif bila tls.enabled di
// config ATAU ada site yang punya sertifikat — port _build_tls_context.
func (s *Server) tlsActive() bool {
	if s.cfg.TLS.Enabled {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.sites {
		if st.Enabled && st.TLSCert != "" && st.TLSKey != "" {
			return true
		}
	}
	return false
}

// getCertificate memilih sertifikat berdasar ServerName (SNI); jatuh kembali
// ke sertifikat default — port sni_callback Python.
func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSpace(hello.ServerName))
	s.mu.RLock()
	st := s.sites[name]
	s.mu.RUnlock()
	if st != nil && st.TLSCert != "" && st.TLSKey != "" {
		if cert, err := s.loadSiteCert(st); err == nil {
			return cert, nil
		}
	}
	if s.defaultCert != nil {
		return s.defaultCert, nil
	}
	return nil, errors.New("perisai: tidak ada sertifikat TLS untuk " + name)
}

// loadSiteCert memuat (dan meng-cache) sertifikat per-site dari file.
func (s *Server) loadSiteCert(st *config.Site) (*tls.Certificate, error) {
	key := st.TLSCert + "\x00" + st.TLSKey
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if c, ok := s.certCache[key]; ok {
		return c, nil
	}
	cert, err := tls.LoadX509KeyPair(
		s.cfg.AbsPath(st.TLSCert), s.cfg.AbsPath(st.TLSKey))
	if err != nil {
		return nil, err
	}
	s.certCache[key] = &cert
	return &cert, nil
}

// ReloadCertificates membuang cache sertifikat SNI agar sertifikat baru
// langsung aktif tanpa restart (dipanggil dashboard setelah tambah/hapus
// cert) — port ProxyServer.reload_tls.
func (s *Server) ReloadCertificates() {
	s.certMu.Lock()
	s.certCache = map[string]*tls.Certificate{}
	s.certMu.Unlock()
}

// ListenAndServe menjalankan proxy: HTTP biasa, atau HTTPS bila tls.enabled
// (sertifikat dari cfg.TLS.Cert/Key) dengan SNI per-site.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.Server.Host, strconv.Itoa(s.cfg.Server.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if !s.tlsActive() {
		return srv.ListenAndServe()
	}
	ln, err := tls.Listen("tcp", addr,
		&tls.Config{GetCertificate: s.getCertificate})
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// -- helper kecil ------------------------------------------------------------

// parseTrustedCIDR mem-parse entri trusted_proxies (CIDR atau IP tunggal,
// seperti ipaddress.ip_network(strict=False) Python).
func parseTrustedCIDR(c string) (netip.Prefix, bool) {
	c = strings.TrimSpace(c)
	if c == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(c); err == nil {
		return p.Masked(), true
	}
	if addr, err := netip.ParseAddr(c); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// hostOnly mengambil nama host tanpa port dari header Host.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.TrimSpace(h)
	}
	// Fallback ala Python: split(":")[0] (abaikan IPv6 dalam kurung).
	if !strings.HasPrefix(hostport, "[") {
		if i := strings.LastIndex(hostport, ":"); i >= 0 {
			return strings.TrimSpace(hostport[:i])
		}
	}
	return strings.TrimSpace(hostport)
}

// flattenHeaders meratakan http.Header menjadi map[string]string dengan key
// lowercase (seperti WAFRequest.create Python).
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vv := range h {
		out[strings.ToLower(k)] = strings.Join(vv, ", ")
	}
	return out
}

// newRequestID membuat id request 12 hex acak (seperti uuid4().hex[:12]).
func newRequestID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano())[:12]
	}
	return hex.EncodeToString(b[:])
}

// -- konversi site dari map storage (port Site.from_dict) --------------------

func mapStr(d map[string]any, k, def string) string {
	v, ok := d[k]
	if !ok || v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func mapBool(d map[string]any, k string, def bool) bool {
	v, ok := d[k]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case int64:
		return t != 0
	case int:
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
	}
	return def
}

func mapInt(d map[string]any, k string, def int) int {
	v, ok := d[k]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case int64:
		return int(t)
	case int:
		return t
	case float64:
		return int(t)
	}
	return def
}

func mapFloat(d map[string]any, k string, def float64) float64 {
	v, ok := d[k]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int64:
		return float64(t)
	case int:
		return float64(t)
	}
	return def
}

// mapList mem-parse kolom JSON-list (disabled_rules, cache_bypass_cookies).
func mapList(d map[string]any, k string) []string {
	v, ok := d[k]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		var out []string
		if json.Unmarshal([]byte(t), &out) == nil {
			return out
		}
		return nil
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// orFloat meniru semantik "float(x) or default" Python (0 -> default).
func orFloat(d map[string]any, k string, def float64) float64 {
	if f := mapFloat(d, k, 0); f != 0 {
		return f
	}
	return def
}

// orInt meniru semantik "int(x) or default" Python (0 -> default).
func orInt(d map[string]any, k string, def int) int {
	if i := mapInt(d, k, 0); i != 0 {
		return i
	}
	return def
}

// siteFromMap membangun config.Site dari baris DB — port Site.from_dict.
func siteFromMap(d map[string]any) *config.Site {
	return &config.Site{
		ID:                 mapStr(d, "id", ""),
		Domain:             strings.ToLower(mapStr(d, "domain", "")),
		UpstreamHost:       mapStr(d, "upstream_host", "127.0.0.1"),
		UpstreamPort:       mapInt(d, "upstream_port", 8000),
		UpstreamTLS:        mapBool(d, "upstream_tls", false),
		UpstreamTLSVerify:  mapBool(d, "upstream_tls_verify", true),
		PreserveHost:       mapBool(d, "preserve_host", true),
		Enabled:            mapBool(d, "enabled", true),
		AgentEnabled:       mapBool(d, "agent_enabled", true),
		DisabledRules:      mapList(d, "disabled_rules"),
		TLSCert:            mapStr(d, "tls_cert", ""),
		TLSKey:             mapStr(d, "tls_key", ""),
		TLSExpiresAt:       mapFloat(d, "tls_expires_at", 0),
		DDoSMode:           mapBool(d, "ddos_mode", false),
		DDoSRPS:            orFloat(d, "ddos_rps", 5),
		CacheEnabled:       mapBool(d, "cache_enabled", false),
		CacheTTL:           orInt(d, "cache_ttl", 60),
		CacheMaxEntries:    orInt(d, "cache_max_entries", 1000),
		CacheMaxObjectKB:   orInt(d, "cache_max_object_kb", 2048),
		CacheBypassCookies: mapList(d, "cache_bypass_cookies"),
		RecaptchaEnabled:   mapBool(d, "recaptcha_enabled", false),
		CFZoneID:           mapStr(d, "cf_zone_id", ""),
	}
}
