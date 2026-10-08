// Test end-to-end package proxy: upstream dummy <- Server <- client HTTP.
package proxy

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// upstreamCapture merekam request terakhir yang sampai ke upstream dummy.
type upstreamCapture struct {
	mu       sync.Mutex
	host     string
	xff      string
	xfp      string
	xperisai string
	body     []byte
	method   string
	count    int
}

func (u *upstreamCapture) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.host = r.Host
	u.xff = r.Header.Get("X-Forwarded-For")
	u.xfp = r.Header.Get("X-Forwarded-Proto")
	u.xperisai = r.Header.Get("X-Perisai")
	u.body = body
	u.method = r.Method
	u.count++
	u.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("UPSTREAM OK"))
}

func (u *upstreamCapture) snapshot() (host, xff, xfp, xp, method string, body []byte, count int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.host, u.xff, u.xfp, u.xperisai, u.method, u.body, u.count
}

type testEnv struct {
	t        *testing.T
	srv      *Server
	cfg      *config.WAFConfig
	store    *storage.Storage
	proxyURL string
	upPort   int
	up       *upstreamCapture
}

// newTestEnv membangun Server + upstream dummy + proxy httptest.
// mutate dipanggil sebelum Server dibuat (untuk tweak config).
func newTestEnv(t *testing.T, mutate func(*config.WAFConfig)) *testEnv {
	t.Helper()
	dir := t.TempDir()

	up := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(up.handler))
	t.Cleanup(upstream.Close)
	uu, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	upPort, err := strconv.Atoi(uu.Port())
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.WAFConfig{
		Server: config.ServerConfig{
			Host: "127.0.0.1", Port: 0,
			UpstreamHost: "127.0.0.1", UpstreamPort: upPort,
			MaxBodyMB: 10, RequestTimeout: 5, UpstreamTLSVerify: true,
		},
		Thresholds: config.Thresholds{AgentScore: 25, BlockScore: 60},
		Agent:      config.AgentConfig{Backend: "heuristic", MinConfidence: 0.55},
		RateLimit:  config.RateLimitConfig{Enabled: false, RPS: 20, Burst: 40},
		Reputation: config.ReputationConfig{Enabled: true, StrikesToBlock: 5, WindowSeconds: 600, BlockSeconds: 3600},
		Learning:   config.LearningConfig{Enabled: false},
		Dashboard:  config.DashboardConfig{Token: "test-secret"},
		Uploads:    config.UploadScanConfig{Enabled: true, MaxFileMB: 10},
		DataDir:    dir,
	}
	if mutate != nil {
		mutate(cfg)
	}
	store, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	eng := rules.NewEngine(cfg, nil)
	orch := agent.NewOrchestrator(cfg, store)
	srv := NewServer(cfg, eng, orch, store)

	proxy := httptest.NewServer(srv.Handler())
	t.Cleanup(proxy.Close)

	return &testEnv{t: t, srv: srv, cfg: cfg, store: store,
		proxyURL: proxy.URL, upPort: upPort, up: up}
}

// noRedirectClient adalah client HTTP yang tidak mengikuti redirect.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}
}

// lastRequest mengembalikan request log terakhir.
func (e *testEnv) lastRequest() map[string]any {
	rows, err := e.store.RecentRequests(1, "")
	if err != nil {
		e.t.Fatal(err)
	}
	if len(rows) == 0 {
		e.t.Fatal("tidak ada request tercatat")
	}
	return rows[0]
}

// addSite mendaftarkan site lalu me-reload routing server.
func (e *testEnv) addSite(domain string, extra map[string]any) {
	m := map[string]any{
		"domain":        domain,
		"upstream_host": "127.0.0.1",
		"upstream_port": e.upPort,
	}
	for k, v := range extra {
		m[k] = v
	}
	if _, err := e.store.UpsertSite(m); err != nil {
		e.t.Fatal(err)
	}
	if err := e.srv.ReloadSites(); err != nil {
		e.t.Fatal(err)
	}
}

// -- test --------------------------------------------------------------------

func TestForwardBenign(t *testing.T) {
	e := newTestEnv(t, nil)

	// GET normal diteruskan (allow)
	resp, err := http.Get(e.proxyURL + "/produk?id=123")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "UPSTREAM OK" {
		t.Fatalf("GET: status=%d body=%q", resp.StatusCode, body)
	}

	host, xff, xfp, xp, _, _, _ := e.up.snapshot()
	if host != "127.0.0.1" { // Python memangkas port dari Host yg diteruskan
		t.Fatalf("Host upstream = %q, mau 127.0.0.1", host)
	}
	if xff != "127.0.0.1" {
		t.Fatalf("X-Forwarded-For = %q, mau 127.0.0.1", xff)
	}
	if xfp != "http" {
		t.Fatalf("X-Forwarded-Proto = %q, mau http", xfp)
	}
	if xp != "1" {
		t.Fatalf("X-Perisai = %q, mau 1", xp)
	}

	// POST: body & method sampai ke upstream
	resp2, err := http.Post(e.proxyURL+"/kirim", "application/x-www-form-urlencoded",
		strings.NewReader("nama=budi&kota=jakarta"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("POST: status=%d", resp2.StatusCode)
	}
	_, _, _, _, method, rbody, _ := e.up.snapshot()
	if method != "POST" || string(rbody) != "nama=budi&kota=jakarta" {
		t.Fatalf("upstream terima method=%q body=%q", method, rbody)
	}

	row := e.lastRequest()
	if row["decision"] != "allow" {
		t.Fatalf("decision tercatat = %v, mau allow", row["decision"])
	}
}

func TestBlacklistBlocks(t *testing.T) {
	e := newTestEnv(t, nil)
	if err := e.store.UpsertIPEntry(map[string]any{
		"id": "b1", "network": "127.0.0.1", "list": "black", "scope": "global",
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(e.proxyURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status=%d, mau 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Perisai") {
		t.Fatalf("body block tidak memuat merek Perisai: %q", body)
	}
	row := e.lastRequest()
	if row["decision"] != "block" || row["top_rule"] != "BLACKLIST" {
		t.Fatalf("log = %v/%v, mau block/BLACKLIST", row["decision"], row["top_rule"])
	}
}

func TestWhitelistBypasses(t *testing.T) {
	e := newTestEnv(t, nil)
	if err := e.store.UpsertIPEntry(map[string]any{
		"id": "w1", "network": "127.0.0.1", "list": "white", "scope": "global",
	}); err != nil {
		t.Fatal(err)
	}

	// Path yang jelas jahat tetap diteruskan karena whitelist bypass semua.
	xss := "/cari?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
	resp, err := http.Get(e.proxyURL + xss)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "UPSTREAM OK" {
		t.Fatalf("whitelist: status=%d body=%q, mau 200/UPSTREAM OK",
			resp.StatusCode, body)
	}
	row := e.lastRequest()
	if row["decision"] != "allow" || row["top_rule"] != "WHITELIST" {
		t.Fatalf("log = %v/%v, mau allow/WHITELIST", row["decision"], row["top_rule"])
	}
}

func TestRateLimit(t *testing.T) {
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.RateLimit.Enabled = true
		c.RateLimit.RPS = 1
		c.RateLimit.Burst = 2
	})
	var codes []int
	for i := 0; i < 3; i++ {
		resp, err := http.Get(e.proxyURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("kode = %v, mau [200 200 429]", codes)
	}
	row := e.lastRequest()
	if row["decision"] != "rate_limited" || row["top_rule"] != "RATE-LIMIT" {
		t.Fatalf("log = %v/%v, mau rate_limited/RATE-LIMIT",
			row["decision"], row["top_rule"])
	}
}

func TestXSSEngineBlock(t *testing.T) {
	e := newTestEnv(t, nil)
	xss := "/cari?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
	resp, err := http.Get(e.proxyURL + xss)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status=%d, mau 403 (block via engine)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Perisai") {
		t.Fatalf("body block tidak memuat merek Perisai")
	}
	row := e.lastRequest()
	if row["decision"] != "block" {
		t.Fatalf("decision = %v, mau block", row["decision"])
	}
	if score, _ := row["score"].(float64); score < 60 {
		t.Fatalf("score = %v, mau >= 60", score)
	}
	if !strings.HasPrefix(row["top_rule"].(string), "XSS-") {
		t.Fatalf("top_rule = %v, mau XSS-*", row["top_rule"])
	}
}

func TestAgentAnalyzeCalled(t *testing.T) {
	e := newTestEnv(t, nil)
	// Probe SQLi abu-abu (zona agent): engine tidak block langsung.
	gray := "/produk?id=1%27%20OR%20%271%27%3D%271"
	resp, err := noRedirectClient().Get(e.proxyURL + gray)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 302 && resp.StatusCode != 403 {
		t.Fatalf("status=%d, mau 302 (challenge) atau 403 (block agent)",
			resp.StatusCode)
	}
	runs, err := e.store.RecentAgentRuns(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) == 0 {
		t.Fatal("orch.Analyze tidak terpanggil: tidak ada agent_runs tercatat")
	}
	row := e.lastRequest()
	t.Logf("decision=%v top_rule=%v score=%v agent_conf=%v",
		row["decision"], row["top_rule"], row["score"], row["agent_conf"])
}

func TestChallengeCookieRoundTrip(t *testing.T) {
	e := newTestEnv(t, nil)
	e.addSite("chal.test", map[string]any{"ddos_mode": 1, "ddos_rps": 100})
	client := noRedirectClient()

	// Request pertama tanpa cookie -> 302 + Set-Cookie challenge.
	req1, _ := http.NewRequest("GET", e.proxyURL+"/halaman?x=1", nil)
	req1.Host = "chal.test"
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != 302 {
		t.Fatalf("tanpa cookie: status=%d, mau 302", resp1.StatusCode)
	}
	setCookie := resp1.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, CookieName+"=") {
		t.Fatalf("Set-Cookie tidak memuat %s: %q", CookieName, setCookie)
	}
	if loc := resp1.Header.Get("Location"); loc != "/halaman?x=1" {
		t.Fatalf("Location = %q, mau URL yang sama", loc)
	}
	// Ambil nilai cookie.
	var token string
	for _, part := range strings.Split(setCookie, ";") {
		if kv := strings.SplitN(strings.TrimSpace(part), "=", 2); len(kv) == 2 &&
			kv[0] == CookieName {
			token = kv[1]
		}
	}
	if token == "" {
		t.Fatal("nilai cookie challenge kosong")
	}
	if !verifyChallengeToken("test-secret", "127.0.0.1", token) {
		t.Fatal("token challenge tidak valid untuk IP klien")
	}

	// Request kedua dengan cookie valid -> diteruskan ke upstream.
	req2, _ := http.NewRequest("GET", e.proxyURL+"/halaman?x=1", nil)
	req2.Host = "chal.test"
	req2.Header.Set("Cookie", CookieName+"="+token)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || string(body) != "UPSTREAM OK" {
		t.Fatalf("dengan cookie: status=%d body=%q, mau 200/UPSTREAM OK",
			resp2.StatusCode, body)
	}
	row := e.lastRequest()
	if row["decision"] != "allow" {
		t.Fatalf("decision = %v, mau allow", row["decision"])
	}
}

func TestUploadPHPBlocked(t *testing.T) {
	e := newTestEnv(t, nil)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("berkas", "shell.php")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(`<?php system($_GET["c"]); ?>`))
	_ = mw.Close()

	req, _ := http.NewRequest("POST", e.proxyURL+"/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("upload .php: status=%d, mau 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Perisai") {
		t.Fatalf("body block tidak memuat merek Perisai")
	}
	row := e.lastRequest()
	if row["decision"] != "block" || row["top_rule"] != "MALWARE-UPLOAD" {
		t.Fatalf("log = %v/%v, mau block/MALWARE-UPLOAD",
			row["decision"], row["top_rule"])
	}
}

func TestUploadCleanAllowed(t *testing.T) {
	e := newTestEnv(t, nil)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("berkas", "foto.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("\x89PNG\r\n\x1a\n" + strings.Repeat("x", 100)))
	_ = mw.Close()

	req, _ := http.NewRequest("POST", e.proxyURL+"/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("upload bersih: status=%d, mau 200", resp.StatusCode)
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.Server.TrustedProxies = []string{"127.0.0.1/32"}
	})
	req, _ := http.NewRequest("GET", e.proxyURL+"/", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d, mau 200", resp.StatusCode)
	}
	if ip := e.lastRequest()["ip"]; ip != "203.0.113.9" {
		t.Fatalf("IP tercatat = %v, mau 203.0.113.9", ip)
	}

	// Tanpa trusted_proxies, header yang sama harus diabaikan (anti-spoof).
	e2 := newTestEnv(t, nil)
	req2, _ := http.NewRequest("GET", e2.proxyURL+"/", nil)
	req2.Header.Set("CF-Connecting-IP", "203.0.113.9")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if ip := e2.lastRequest()["ip"]; ip == "203.0.113.9" {
		t.Fatalf("header spoof lolos: IP tercatat = %v", ip)
	}
}

func TestDisabledRulesFiltering(t *testing.T) {
	// Unit: hit rule yang dimatikan dibuang, skor & aksi dihitung ulang.
	req := &rules.Request{Method: "GET", Path: "/x", Query: "q=1"}
	triage := rules.TriageResult{
		Score: 80, Action: "block",
		Hits: []rules.Hit{
			{RuleID: "XSS-001", Weight: 40, Severity: "critical"},
			{RuleID: "XSS-005", Weight: 25, Severity: "high"},
			{RuleID: "XSS-007", Weight: 15, Severity: "medium"},
		},
	}
	out := filterDisabled(req, triage,
		map[string]bool{"XSS-001": true, "XSS-005": true},
		config.Thresholds{AgentScore: 25, BlockScore: 60})
	if len(out.Hits) != 1 || out.Hits[0].RuleID != "XSS-007" {
		t.Fatalf("hits = %+v, mau hanya XSS-007", out.Hits)
	}
	if out.Score != 15 {
		t.Fatalf("score = %v, mau 15", out.Score)
	}
	if out.Action != "allow" {
		t.Fatalf("action = %q, mau allow", out.Action)
	}
	// Tanpa disabled: hasil tidak berubah.
	same := filterDisabled(req, triage, nil,
		config.Thresholds{AgentScore: 25, BlockScore: 60})
	if same.Action != "block" || same.Score != 80 {
		t.Fatalf("tanpa disabled berubah: %+v", same)
	}
}

func TestDisabledRulesEndToEnd(t *testing.T) {
	e := newTestEnv(t, nil)
	xss := "/cari?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"

	// Sanity: sebelum dimatikan, request diblokir.
	resp, _ := http.Get(e.proxyURL + xss)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("pra-kondisi: status=%d, mau 403", resp.StatusCode)
	}

	// Matikan ketiga rule XSS yang cocok -> request lolos.
	for _, id := range []string{"XSS-001", "XSS-005", "XSS-007"} {
		if !e.srv.SetRuleDisabled(id, true) {
			t.Fatalf("SetRuleDisabled(%s) gagal", id)
		}
	}
	if got := e.srv.GlobalDisabledRules(); len(got) != 3 {
		t.Fatalf("GlobalDisabledRules = %v", got)
	}
	if e.srv.SetRuleDisabled("TIDAK-ADA", true) {
		t.Fatal("SetRuleDisabled(rule tak dikenal) harus false")
	}

	resp2, err := http.Get(e.proxyURL + xss)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || string(body) != "UPSTREAM OK" {
		t.Fatalf("setelah disabled: status=%d body=%q, mau 200/UPSTREAM OK",
			resp2.StatusCode, body)
	}
}

func TestChallengeToken(t *testing.T) {
	const secret = "rahasia-uji"
	tok := issueChallengeToken(secret, "10.0.0.5")
	if !verifyChallengeToken(secret, "10.0.0.5", tok) {
		t.Fatal("token segar harus valid")
	}
	if verifyChallengeToken(secret, "10.0.0.6", tok) {
		t.Fatal("token untuk IP lain harus ditolak")
	}
	if verifyChallengeToken(secret, "10.0.0.5", tok+"x") {
		t.Fatal("token yang diutak-atik harus ditolak")
	}
	if verifyChallengeToken(secret, "10.0.0.5", "bukan-token") {
		t.Fatal("token malformed harus ditolak")
	}
	// Token kedaluwarsa.
	past := time.Now().Unix() - 10
	expired := strconv.FormatInt(past, 10) + "." + challengeSig(secret, "10.0.0.5", past)
	if verifyChallengeToken(secret, "10.0.0.5", expired) {
		t.Fatal("token kedaluwarsa harus ditolak")
	}
}

func TestCacheHit(t *testing.T) {
	e := newTestEnv(t, nil)
	e.addSite("cache.test", map[string]any{"cache_enabled": 1, "cache_ttl": 60})

	get := func() (int, string, string) {
		req, _ := http.NewRequest("GET", e.proxyURL+"/berita", nil)
		req.Host = "cache.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body), resp.Header.Get("X-Perisai-Cache")
	}

	code1, body1, h1 := get()
	if code1 != 200 || body1 != "UPSTREAM OK" || h1 != "MISS" {
		t.Fatalf("req1: %d %q cache=%q, mau 200/UPSTREAM OK/MISS", code1, body1, h1)
	}
	code2, body2, h2 := get()
	if code2 != 200 || body2 != "UPSTREAM OK" || h2 != "HIT" {
		t.Fatalf("req2: %d %q cache=%q, mau 200/UPSTREAM OK/HIT", code2, body2, h2)
	}
	_, _, _, _, _, _, count := e.up.snapshot()
	if count != 1 {
		t.Fatalf("upstream dipanggil %d kali, mau 1 (req2 dari cache)", count)
	}
	if row := e.lastRequest()["decision"]; row != "cache_hit" {
		t.Fatalf("decision = %v, mau cache_hit", row)
	}
}

func TestSiteRoutingFallback(t *testing.T) {
	e := newTestEnv(t, nil)
	e.addSite("toko.test", map[string]any{})

	// Host cocok -> diteruskan ke upstream site.
	req, _ := http.NewRequest("GET", e.proxyURL+"/", nil)
	req.Host = "toko.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("host cocok: status=%d, mau 200", resp.StatusCode)
	}
}

// TestBotSpoofedUAChallenged: UA mengaku browser tapi JA3 khas tool otomatis
// -> di-challenge, tidak diteruskan ke upstream.
func TestBotSpoofedUAChallenged(t *testing.T) {
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.Bot = config.BotConfig{Enabled: true, ChallengeScore: 65, BlockScore: 90}
	})
	ja3 := "771,4865-4866,0-23-65281-10-11,29-23,0" // pendek, khas otomatis
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyJA3{}, ja3))
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 challenge", rec.Code)
	}
	if _, _, _, _, _, _, count := e.up.snapshot(); count != 0 {
		t.Fatalf("request bot sampai ke upstream (%d), harus ditahan", count)
	}
	if lr := e.lastRequest(); lr["decision"] != "challenge" {
		t.Fatalf("decision log = %v, want challenge", lr["decision"])
	}
}

// TestBotBrowserNormalDiteruskan: browser asli (JA3 panjang + UA cocok)
// tidak diganggu deteksi bot.
func TestBotBrowserNormalDiteruskan(t *testing.T) {
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.Bot = config.BotConfig{Enabled: true, ChallengeScore: 65, BlockScore: 90}
	})
	ja3 := "771,4865-4866-4867,0-5-10-11-13-16-18-21-23-27-43-45,29-23-24,0"
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "id-ID")
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyJA3{}, ja3))
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if _, _, _, _, _, _, count := e.up.snapshot(); count != 1 {
		t.Fatalf("browser normal tidak sampai upstream (count=%d), status=%d", count, rec.Code)
	}
}

// TestGeoBlockCountry: IP dari negara yang diblokir -> 403, tidak ke upstream.
func TestGeoBlockCountry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","countryCode":"ID"}`))
	}))
	defer ts.Close()
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.Geo = config.GeoConfig{Enabled: true, Provider: "api",
			APIURL: ts.URL, BlockedCountries: []string{"ID"}}
	})
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "8.8.8.8:4321" // IP publik agar GeoIP jalan
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if _, _, _, _, _, _, count := e.up.snapshot(); count != 0 {
		t.Fatalf("request terblokir sampai ke upstream (%d)", count)
	}
	if lr := e.lastRequest(); lr["decision"] != "block" {
		t.Fatalf("decision log = %v, want block", lr["decision"])
	}
}

// TestGeoBlockFailOpen: API GeoIP gagal -> request tetap lolos (fail-open).
func TestGeoBlockFailOpen(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.Geo = config.GeoConfig{Enabled: true, Provider: "api",
			APIURL: ts.URL, BlockedCountries: []string{"ID"}}
	})
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "8.8.8.8:4321"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if _, _, _, _, _, _, count := e.up.snapshot(); count != 1 {
		t.Fatalf("fail-open rusak: upstream count=%d, want 1 (status=%d)", count, rec.Code)
	}
}

// TestGeoBlockPerSiteOverride: daftar per-site mengalahkan daftar global.
func TestGeoBlockPerSiteOverride(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","countryCode":"ID"}`))
	}))
	defer ts.Close()
	e := newTestEnv(t, func(c *config.WAFConfig) {
		c.Geo = config.GeoConfig{Enabled: true, Provider: "api",
			APIURL: ts.URL, BlockedCountries: []string{"ID"}}
	})
	// Site tanpa override sendiri -> ikut global (ID diblokir).
	site := &config.Site{ID: "s1", Domain: "example.com", Enabled: true,
		UpstreamHost: "127.0.0.1", UpstreamPort: e.upPort}
	e.srv.mu.Lock()
	e.srv.sites["example.com"] = site
	e.srv.byID["s1"] = site
	e.srv.mu.Unlock()
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "8.8.8.8:4321"
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("global block: status = %d, want 403", rec.Code)
	}
	// Site dengan override kosong... (nil -> ikut global). Override berisi
	// negara lain -> ID lolos.
	site.BlockedCountries = []string{"CN"}
	req2 := httptest.NewRequest("GET", "http://example.com/", nil)
	req2.RemoteAddr = "8.8.8.8:4321"
	rec2 := httptest.NewRecorder()
	e.srv.ServeHTTP(rec2, req2)
	if _, _, _, _, _, _, count := e.up.snapshot(); count != 1 {
		t.Fatalf("override per-site: upstream count=%d, want 1", count)
	}
}
