// Test dashboard: auth, validasi config AI/System One, CRUD site, toggle rule,
// SPA serving. Vektor diambil dari tests/test_auth.py & test_ai_settings.py
// (Python) — perilaku yang diuji disamakan.
package dashboard

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/auth"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// testSetup membuat Dashboard lengkap di direktori temporer.
type testSetup struct {
	d   *Dashboard
	cfg *config.WAFConfig
	dir string
}

func newTestSetup(t *testing.T, passwordHash string) *testSetup {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	store, err := storage.New(dataDir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := &config.WAFConfig{
		DataDir:    dataDir,
		ConfigPath: filepath.Join(dir, "config.yaml"),
	}
	cfg.Dashboard.Token = "tok-test"
	cfg.Dashboard.Username = "owner"
	cfg.Dashboard.PasswordHash = passwordHash
	cfg.Agent.Backend = "auto"
	cfg.Agent.MinConfidence = 0.55
	cfg.Agent.LLM = config.LLMConfig{
		BaseURL: "http://127.0.0.1:20127/v1",
		APIKey:  "KEY-LAMA",
		Model:   "model-lama",
		Timeout: 20,
	}
	cfg.Agent.SystemOne = config.SystemOneConfig{
		Enabled:  true,
		Endpoint: "http://127.0.0.1:1/v1/systemone", // tak terjangkau -> gagal cepat
		APIKey:   "S1-KEY",
		Model:    "oc/jev-1.13-free",
		Timeout:  10,
	}
	cfg.Geo.Enabled = false // matikan lookup geo di test (tanpa jaringan)

	eng := rules.NewEngine(cfg, nil)
	orch := agent.NewOrchestrator(cfg, store)
	spa := fstest.MapFS{
		"index.html":    {Data: []byte("<html><body><div id=\"app\"></div></body></html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	d := New(cfg, store, orch, eng, spa)
	return &testSetup{d: d, cfg: cfg, dir: dir}
}

func testHash(t *testing.T) string {
	t.Helper()
	h, err := auth.HashPassword("test1234")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}

// do melakukan request ke handler dashboard; token ditambah sebagai ?token=.
func (s *testSetup) do(t *testing.T, method, path string, body any, token string) (int, []byte) {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = strings.NewReader(string(raw))
	} else {
		rdr = strings.NewReader("")
	}
	if token != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "token=" + token
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.d.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// doJSON seperti do, dengan respons di-decode ke map.
func (s *testSetup) doJSON(t *testing.T, method, path string, body any, token string) (int, map[string]any) {
	t.Helper()
	code, raw := s.do(t, method, path, body, token)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s %s: respons bukan JSON: %q (status %d)", method, path, raw, code)
	}
	return code, m
}

func mustOK(t *testing.T, m map[string]any) {
	t.Helper()
	if m["ok"] != true {
		t.Fatalf("diharapkan ok=true, dapat: %v", m)
	}
}

// -- auth --------------------------------------------------------------------

func TestTanpaAuthDitolak(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	for _, p := range []string{"/api/stats", "/api/rules", "/api/ai-config"} {
		code, m := s.doJSON(t, "GET", p, nil, "")
		if code != 401 || m["error"] != "unauthorized" {
			t.Fatalf("GET %s tanpa token: code=%d body=%v", p, code, m)
		}
		code, _ = s.doJSON(t, "GET", p, nil, "salah")
		if code != 401 {
			t.Fatalf("GET %s token salah: code=%d", p, code)
		}
		code, _ = s.doJSON(t, "GET", "/api/stats", nil, "tok-test")
		if code != 200 {
			t.Fatalf("GET /api/stats token benar: code=%d", code)
		}
	}
	// header Authorization: Bearer juga diterima
	code, _ := s.doJSON(t, "GET", "/api/stats", nil, "")
	if code != 401 {
		t.Fatalf("tanpa token harus 401, dapat %d", code)
	}
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer tok-test")
	rec := httptest.NewRecorder()
	s.d.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Authorization: Bearer harus 200, dapat %d", rec.Code)
	}
}

func TestLoginSuksesDanSession(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "POST", "/api/login",
		map[string]any{"username": "owner", "password": "test1234"}, "")
	if code != 200 {
		t.Fatalf("login: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["username"] != "owner" || m["token"] == "" || m["expires_in"] == nil {
		t.Fatalf("respons login tak lengkap: %v", m)
	}
	tok := m["token"].(string)
	// session token bisa dipakai untuk API
	code, _ = s.doJSON(t, "GET", "/api/ai-config", nil, tok)
	if code != 200 {
		t.Fatalf("session token harus 200, dapat %d", code)
	}
	// logout mencabut sesi
	code, _ = s.doJSON(t, "POST", "/api/logout", map[string]any{}, tok)
	if code != 200 {
		t.Fatalf("logout: code=%d", code)
	}
	code, _ = s.doJSON(t, "GET", "/api/ai-config", nil, tok)
	if code != 401 {
		t.Fatalf("sesudah logout harus 401, dapat %d", code)
	}
}

func TestLoginPasswordSalah(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	for _, creds := range []map[string]any{
		{"username": "owner", "password": "salah"},
		{"username": "takada", "password": "test1234"},
		{"username": "", "password": ""},
	} {
		code, m := s.doJSON(t, "POST", "/api/login", creds, "")
		if code != 401 {
			t.Fatalf("login salah harus 401, dapat %d (%v)", code, creds)
		}
		// pesan generik: tidak membocorkan user mana yang ada
		if m["error"] != "username atau password salah" {
			t.Fatalf("pesan harus generik, dapat: %v", m["error"])
		}
	}
}

func TestLoginThrottle(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	bad := map[string]any{"username": "owner", "password": "salah"}
	for i := 0; i < 5; i++ {
		code, _ := s.doJSON(t, "POST", "/api/login", bad, "")
		if code != 401 {
			t.Fatalf("percobaan %d harus 401, dapat %d", i+1, code)
		}
	}
	code, m := s.doJSON(t, "POST", "/api/login", bad, "")
	if code != 429 {
		t.Fatalf("percobaan ke-6 harus 429, dapat %d", code)
	}
	if !strings.Contains(m["error"].(string), "terlalu banyak") {
		t.Fatalf("pesan 429 harus menyebut 'terlalu banyak': %v", m["error"])
	}
}

func TestLoginBelumDikonfigurasi(t *testing.T) {
	s := newTestSetup(t, "") // tanpa password hash
	code, m := s.doJSON(t, "POST", "/api/login",
		map[string]any{"username": "admin", "password": "x"}, "")
	if code != 503 {
		t.Fatalf("harus 503, dapat %d", code)
	}
	if !strings.Contains(m["error"].(string), "setpassword") {
		t.Fatalf("pesan 503 harus menyebut setpassword: %v", m["error"])
	}
}

// -- /api/ai-config ------------------------------------------------------------

func TestAIConfigGetMasked(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "GET", "/api/ai-config", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if m["backend"] != "auto" {
		t.Fatalf("backend=%v", m["backend"])
	}
	llm := m["llm"].(map[string]any)
	if llm["model"] != "model-lama" {
		t.Fatalf("model=%v", llm["model"])
	}
	if llm["api_key_set"] != true {
		t.Fatalf("api_key_set=%v", llm["api_key_set"])
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "KEY-LAMA") {
		t.Fatalf("key mentah bocor di respons: %s", raw)
	}
	if _, ada := llm["api_key"]; ada {
		t.Fatalf("field api_key tidak boleh ada: %v", llm)
	}
	code, _ = s.doJSON(t, "GET", "/api/ai-config", nil, "")
	if code != 401 {
		t.Fatalf("tanpa token harus 401, dapat %d", code)
	}
}

func TestAIConfigPostAppliesAndPersists(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// tulis config.yaml minimal agar persist bisa diuji merge-nya
	if err := os.WriteFile(s.cfg.ConfigPath,
		[]byte("agent:\n  backend: auto\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, m := s.doJSON(t, "POST", "/api/ai-config", map[string]any{
		"backend": "llm", "base_url": "https://9router.com/v1",
		"model": "cx/deepseek-chat", "timeout": 25,
		"min_confidence": 0.6, "api_key": "KEY-BARU",
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["persisted"] != true {
		t.Fatalf("persisted harus true: %v", m)
	}
	if m["restart_needed"] != false {
		t.Fatalf("restart_needed harus false: %v", m)
	}
	// in-memory langsung berubah
	if s.cfg.Agent.Backend != "llm" ||
		s.cfg.Agent.LLM.Model != "cx/deepseek-chat" ||
		s.cfg.Agent.LLM.APIKey != "KEY-BARU" {
		t.Fatalf("config in-memory tak berubah: %+v", s.cfg.Agent)
	}
	// file ikut terupdate
	raw, err := os.ReadFile(s.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "https://9router.com/v1") {
		t.Fatalf("config.yaml tak terupdate:\n%s", raw)
	}
	// view di respons ikut termasking
	view := m["config"].(map[string]any)
	if view["llm"].(map[string]any)["api_key_set"] != true {
		t.Fatalf("view: %v", view)
	}
}

func TestAIConfigPostKeepsKeyWhenEmpty(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, _ := s.doJSON(t, "POST", "/api/ai-config", map[string]any{
		"backend": "auto", "base_url": "http://127.0.0.1:20127/v1",
		"model": "m", "timeout": 20, "min_confidence": 0.55,
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if s.cfg.Agent.LLM.APIKey != "KEY-LAMA" {
		t.Fatalf("key tidak boleh tertimpa: %q", s.cfg.Agent.LLM.APIKey)
	}
	code, _ = s.doJSON(t, "POST", "/api/ai-config", map[string]any{
		"backend": "auto", "base_url": "http://127.0.0.1:20127/v1",
		"model": "m", "timeout": 20, "min_confidence": 0.55,
		"clear_api_key": true,
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if s.cfg.Agent.LLM.APIKey != "" {
		t.Fatalf("clear_api_key harus mengosongkan: %q", s.cfg.Agent.LLM.APIKey)
	}
}

func TestAIConfigPostValidation(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	good := map[string]any{
		"backend": "auto", "base_url": "http://x/v1",
		"model": "m", "timeout": 20, "min_confidence": 0.5,
	}
	cases := []map[string]any{
		{"backend": "quantum"},
		{"base_url": "ftp://x/v1"},
		{"backend": "llm", "base_url": ""},
		{"model": ""},
		{"timeout": 999},
		{"min_confidence": 2},
	}
	for i, mod := range cases {
		body := map[string]any{}
		for k, v := range good {
			body[k] = v
		}
		for k, v := range mod {
			body[k] = v
		}
		code, m := s.doJSON(t, "POST", "/api/ai-config", body, "tok-test")
		if code != 400 || m["error"] == "" {
			t.Fatalf("kasus %d (%v): code=%d body=%v", i, mod, code, m)
		}
	}
}

func TestAIModels(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// server model tiruan
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"id":"b-model","owned_by":"o"},{"id":"a-model"}]}`))
	}))
	defer srv.Close()

	code, m := s.doJSON(t, "POST", "/api/ai-models",
		map[string]any{"base_url": srv.URL + "/v1", "api_key": "k"}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["count"] != float64(2) {
		t.Fatalf("count=%v", m["count"])
	}
	models := m["models"].([]any)
	if models[0].(map[string]any)["id"] != "a-model" {
		t.Fatalf("model harus terurut: %v", models)
	}
	// base_url tak valid -> 400
	code, _ = s.doJSON(t, "POST", "/api/ai-models",
		map[string]any{"base_url": "notaurl"}, "tok-test")
	if code != 400 {
		t.Fatalf("base_url tak valid harus 400, dapat %d", code)
	}
	// endpoint mati -> 502 {ok:false}
	code, m = s.doJSON(t, "POST", "/api/ai-models",
		map[string]any{"base_url": "http://127.0.0.1:1/v1"}, "tok-test")
	if code != 502 || m["ok"] != false {
		t.Fatalf("endpoint mati harus 502 ok=false: code=%d body=%v", code, m)
	}
}

// -- /api/systemone-config -----------------------------------------------------

func TestSystemOneConfigMasked(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "GET", "/api/systemone-config", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if m["enabled"] != true || m["model"] != "oc/jev-1.13-free" {
		t.Fatalf("body=%v", m)
	}
	if m["api_key_set"] != true {
		t.Fatalf("api_key_set=%v", m["api_key_set"])
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "S1-KEY") {
		t.Fatalf("key mentah bocor: %s", raw)
	}
}

func TestSystemOneConfigPost(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "POST", "/api/systemone-config", map[string]any{
		"enabled": true, "endpoint": "https://ai.skyzo.biz.id/v1/systemone",
		"model": "oc/jev-1.13-free", "timeout": 12, "api_key": "S1-BARU",
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if s.cfg.Agent.SystemOne.APIKey != "S1-BARU" ||
		s.cfg.Agent.SystemOne.Timeout != 12 {
		t.Fatalf("config tak berubah: %+v", s.cfg.Agent.SystemOne)
	}
	// validasi: enabled tapi endpoint kosong -> 400
	code, m = s.doJSON(t, "POST", "/api/systemone-config", map[string]any{
		"enabled": true, "endpoint": "", "model": "m", "timeout": 10,
	}, "tok-test")
	if code != 400 || m["error"] == "" {
		t.Fatalf("harus 400: code=%d body=%v", code, m)
	}
	// key lama dipertahankan bila api_key absen
	code, _ = s.doJSON(t, "POST", "/api/systemone-config", map[string]any{
		"enabled": false, "endpoint": "", "model": "m", "timeout": 10,
	}, "tok-test")
	if code != 200 || s.cfg.Agent.SystemOne.APIKey != "S1-BARU" {
		t.Fatalf("key harus dipertahankan: %+v", s.cfg.Agent.SystemOne)
	}
}

func TestSystemOneTestEndpoint(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// endpoint tak terjangkau -> tetap 200 dengan ok=false (gagal cepat)
	code, m := s.doJSON(t, "GET", "/api/systemone/test", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if m["backend"] != "systemone" {
		t.Fatalf("backend=%v", m["backend"])
	}
	if _, ada := m["ok"]; !ada {
		t.Fatalf("respons harus punya field ok: %v", m)
	}
	code, m = s.doJSON(t, "GET", "/api/agent/test", nil, "tok-test")
	if code != 200 || m["backend"] != "llm" {
		t.Fatalf("agent/test: code=%d body=%v", code, m)
	}
}

// -- sites ---------------------------------------------------------------------

func createSite(t *testing.T, s *testSetup) string {
	t.Helper()
	code, m := s.doJSON(t, "POST", "/api/sites", map[string]any{
		"domain": "contoh.test", "upstream_host": "127.0.0.1",
		"upstream_port": 8000,
	}, "tok-test")
	if code != 200 {
		t.Fatalf("buat site: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	return m["id"].(string)
}

func TestSitesCRUD(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// validasi
	code, m := s.doJSON(t, "POST", "/api/sites",
		map[string]any{"upstream_port": 8000}, "tok-test")
	if code != 400 || m["error"] != "domain wajib diisi" {
		t.Fatalf("tanpa domain harus 400: code=%d body=%v", code, m)
	}
	code, _ = s.doJSON(t, "POST", "/api/sites",
		map[string]any{"domain": "x.test", "upstream_port": "abc"}, "tok-test")
	if code != 400 {
		t.Fatalf("upstream_port tak valid harus 400, dapat %d", code)
	}

	sid := createSite(t, s)
	// GET /api/sites memuatnya
	code, raw := s.do(t, "GET", "/api/sites", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	var sites []map[string]any
	if err := json.Unmarshal(raw, &sites); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, site := range sites {
		if site["id"] == sid {
			found = true
			if site["domain"] != "contoh.test" {
				t.Fatalf("domain=%v", site["domain"])
			}
			if _, ada := site["requests_24h"]; !ada {
				t.Fatalf("requests_24h hilang: %v", site)
			}
		}
	}
	if !found {
		t.Fatalf("site %s tak ada di daftar", sid)
	}
	// GET /api/sites/{id}
	code, m = s.doJSON(t, "GET", "/api/sites/"+sid, nil, "tok-test")
	if code != 200 || m["domain"] != "contoh.test" {
		t.Fatalf("GET site: code=%d body=%v", code, m)
	}
	code, _ = s.doJSON(t, "GET", "/api/sites/takada", nil, "tok-test")
	if code != 404 {
		t.Fatalf("site tak ada harus 404, dapat %d", code)
	}
	// DELETE
	code, m = s.doJSON(t, "DELETE", "/api/sites/"+sid, nil, "tok-test")
	if code != 200 {
		t.Fatalf("delete: code=%d", code)
	}
	mustOK(t, m)
	code, _ = s.doJSON(t, "GET", "/api/sites/"+sid, nil, "tok-test")
	if code != 404 {
		t.Fatalf("sesudah hapus harus 404, dapat %d", code)
	}
}

func TestSiteDDoSToggle(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	sid := createSite(t, s)
	code, m := s.doJSON(t, "POST", "/api/sites/"+sid+"/ddos", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["ddos_mode"] != true {
		t.Fatalf("ddos_mode harus true: %v", m)
	}
	// toggle lagi -> mati
	code, m = s.doJSON(t, "POST", "/api/sites/"+sid+"/ddos", nil, "tok-test")
	if code != 200 || m["ddos_mode"] != false {
		t.Fatalf("toggle off: code=%d body=%v", code, m)
	}
	// body eksplisit {enabled, ddos_rps}
	code, m = s.doJSON(t, "POST", "/api/sites/"+sid+"/ddos",
		map[string]any{"enabled": true, "ddos_rps": 10}, "tok-test")
	if code != 200 || m["ddos_mode"] != true || m["ddos_rps"] != float64(10) {
		t.Fatalf("ddos eksplisit: code=%d body=%v", code, m)
	}
	// ddos_rps di luar rentang diabaikan
	code, m = s.doJSON(t, "POST", "/api/sites/"+sid+"/ddos",
		map[string]any{"ddos_rps": 99999}, "tok-test")
	if code != 200 || m["ddos_rps"] != float64(10) {
		t.Fatalf("rps invalid harus diabaikan: code=%d body=%v", code, m)
	}
	code, _ = s.doJSON(t, "POST", "/api/sites/takada/ddos", nil, "tok-test")
	if code != 404 {
		t.Fatalf("site tak ada harus 404, dapat %d", code)
	}
}

func TestSiteToggle(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	sid := createSite(t, s)
	code, m := s.doJSON(t, "POST", "/api/sites/"+sid+"/toggle", nil, "tok-test")
	if code != 200 || m["enabled"] != false {
		t.Fatalf("toggle: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	code, _ = s.doJSON(t, "POST", "/api/sites/takada/toggle", nil, "tok-test")
	if code != 404 {
		t.Fatalf("harus 404, dapat %d", code)
	}
}

// -- stats & rules ---------------------------------------------------------------

func TestStatsDanRules(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "GET", "/api/stats", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if _, ada := m["total"]; !ada {
		t.Fatalf("total hilang: %v", m)
	}
	if m["rules_loaded"] == nil || m["rules_loaded"].(float64) <= 0 {
		t.Fatalf("rules_loaded=%v", m["rules_loaded"])
	}

	code, raw := s.do(t, "GET", "/api/rules", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	var rulesList []map[string]any
	if err := json.Unmarshal(raw, &rulesList); err != nil {
		t.Fatal(err)
	}
	if len(rulesList) == 0 {
		t.Fatalf("daftar rule kosong")
	}
	rid := rulesList[0]["id"].(string)
	if rulesList[0]["disabled"] != false {
		t.Fatalf("rule baru harus enabled: %v", rulesList[0])
	}
	// toggle -> disabled
	code, m = s.doJSON(t, "POST", "/api/rules/"+rid+"/toggle", nil, "tok-test")
	if code != 200 || m["disabled"] != true {
		t.Fatalf("toggle: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if len(s.d.DisabledRules()) != 1 || s.d.DisabledRules()[0] != rid {
		t.Fatalf("DisabledRules=%v", s.d.DisabledRules())
	}
	// toggle eksplisit -> enabled lagi
	code, m = s.doJSON(t, "POST", "/api/rules/"+rid+"/toggle",
		map[string]any{"disabled": false}, "tok-test")
	if code != 200 || m["disabled"] != false {
		t.Fatalf("toggle off: code=%d body=%v", code, m)
	}
	// rule tak dikenal -> 404
	code, _ = s.doJSON(t, "POST", "/api/rules/TIDAK-ADA/toggle", nil, "tok-test")
	if code != 404 {
		t.Fatalf("rule tak dikenal harus 404, dapat %d", code)
	}
}

// -- iplists ---------------------------------------------------------------------

func TestIPLists(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// tambah valid
	code, m := s.doJSON(t, "POST", "/api/iplists", map[string]any{
		"network": "203.0.113.0/24", "list": "black", "note": "uji",
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	eid := m["id"].(string)
	// IP tunggal dinormalisasi ke /32
	code, m = s.doJSON(t, "POST", "/api/iplists", map[string]any{
		"network": "198.51.100.7", "list": "white",
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	// invalid
	for _, bad := range []map[string]any{
		{"network": "bukan-ip", "list": "black"},
		{"network": "10.0.0.1", "list": "gray"},
		{"network": "", "list": "black"},
	} {
		code, _ := s.doJSON(t, "POST", "/api/iplists", bad, "tok-test")
		if code != 400 {
			t.Fatalf("input %v harus 400, dapat %d", bad, code)
		}
	}
	// GET memuat entri
	code, raw := s.do(t, "GET", "/api/iplists", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("diharapkan 2 entri, dapat %d", len(entries))
	}
	// hapus
	code, m = s.doJSON(t, "DELETE", "/api/iplists/"+eid, nil, "tok-test")
	if code != 200 {
		t.Fatalf("delete: code=%d", code)
	}
	mustOK(t, m)
}

// -- ip groups ---------------------------------------------------------------------

func TestIPGroups(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// nama wajib
	code, _ := s.doJSON(t, "POST", "/api/ip-groups",
		map[string]any{"name": "  "}, "tok-test")
	if code != 400 {
		t.Fatalf("nama kosong harus 400, dapat %d", code)
	}
	code, m := s.doJSON(t, "POST", "/api/ip-groups", map[string]any{
		"name": "penyerang", "kind": "black", "description": "uji",
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	gid := m["id"].(string)
	// tambah member
	code, m = s.doJSON(t, "POST", "/api/ip-groups/"+gid+"/members",
		map[string]any{"cidr": "203.0.113.9"}, "tok-test")
	if code != 200 {
		t.Fatalf("add member: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["cidr"] != "203.0.113.9/32" {
		t.Fatalf("cidr harus dinormalisasi: %v", m["cidr"])
	}
	code, _ = s.doJSON(t, "POST", "/api/ip-groups/"+gid+"/members",
		map[string]any{"cidr": "xx"}, "tok-test")
	if code != 400 {
		t.Fatalf("cidr invalid harus 400, dapat %d", code)
	}
	// GET satu grup
	code, m = s.doJSON(t, "GET", "/api/ip-groups/"+gid, nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	members := m["members"].([]any)
	if len(members) != 1 || members[0] != "203.0.113.9/32" {
		t.Fatalf("members=%v", members)
	}
	code, _ = s.doJSON(t, "GET", "/api/ip-groups/takada", nil, "tok-test")
	if code != 404 {
		t.Fatalf("grup tak ada harus 404, dapat %d", code)
	}
	// PUT rename
	code, m = s.doJSON(t, "PUT", "/api/ip-groups/"+gid,
		map[string]any{"name": "penyerang2"}, "tok-test")
	if code != 200 {
		t.Fatalf("put: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	// hapus member via query
	code, m = s.doJSON(t, "DELETE",
		"/api/ip-groups/"+gid+"/members?cidr=203.0.113.9/32", nil, "tok-test")
	if code != 200 {
		t.Fatalf("del member: code=%d body=%v", code, m)
	}
	// hapus grup
	code, m = s.doJSON(t, "DELETE", "/api/ip-groups/"+gid, nil, "tok-test")
	if code != 200 {
		t.Fatalf("del group: code=%d", code)
	}
	mustOK(t, m)
}

// -- cache ---------------------------------------------------------------------

func TestCacheEndpoints(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	sid := createSite(t, s)
	// GET config site tak ada -> 404
	code, _ := s.doJSON(t, "GET", "/api/cache/config?site_id=takada", nil, "tok-test")
	if code != 404 {
		t.Fatalf("harus 404, dapat %d", code)
	}
	code, m := s.doJSON(t, "GET", "/api/cache/config?site_id="+sid, nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	for _, k := range []string{"site_id", "enabled", "ttl", "max_entries", "max_object_kb", "bypass_cookies"} {
		if _, ada := m[k]; !ada {
			t.Fatalf("key %s hilang: %v", k, m)
		}
	}
	// POST config
	code, m = s.doJSON(t, "POST", "/api/cache/config", map[string]any{
		"site_id": sid, "enabled": true, "ttl": 120,
		"bypass_cookies": []string{"sesi"},
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	code, m = s.doJSON(t, "GET", "/api/cache/config?site_id="+sid, nil, "tok-test")
	if code != 200 || m["enabled"] != true || m["ttl"] != float64(120) {
		t.Fatalf("config tak tersimpan: %v", m)
	}
	bc := m["bypass_cookies"].([]any)
	if len(bc) != 1 || bc[0] != "sesi" {
		t.Fatalf("bypass_cookies=%v", bc)
	}
	// stats
	code, m = s.doJSON(t, "GET", "/api/cache/stats", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	for _, k := range []string{"hits", "misses", "hit_ratio", "entries", "bytes"} {
		if _, ada := m[k]; !ada {
			t.Fatalf("key %s hilang: %v", k, m)
		}
	}
	// purge
	code, m = s.doJSON(t, "POST", "/api/cache/purge",
		map[string]any{"site_id": sid}, "tok-test")
	if code != 200 || m["purged"] == nil {
		t.Fatalf("purge: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	code, _ = s.doJSON(t, "POST", "/api/cache/purge",
		map[string]any{"site_id": "takada"}, "tok-test")
	if code != 404 {
		t.Fatalf("purge site tak ada harus 404, dapat %d", code)
	}
}

// -- recaptcha ---------------------------------------------------------------------

func TestRecaptchaConfig(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "GET", "/api/recaptcha/config", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	for _, k := range []string{"enabled", "site_key", "site_key_set", "secret_key_set", "mode"} {
		if _, ada := m[k]; !ada {
			t.Fatalf("key %s hilang: %v", k, m)
		}
	}
	// mode invalid
	code, _ = s.doJSON(t, "POST", "/api/recaptcha/config",
		map[string]any{"mode": "v9"}, "tok-test")
	if code != 400 {
		t.Fatalf("mode invalid harus 400, dapat %d", code)
	}
	// simpan
	code, m = s.doJSON(t, "POST", "/api/recaptcha/config", map[string]any{
		"enabled": true, "site_key": "SITE-123", "secret_key": "SECRET-1",
		"mode": "v3",
	}, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if !s.cfg.Recaptcha.Enabled || s.cfg.Recaptcha.SiteKey != "SITE-123" ||
		s.cfg.Recaptcha.SecretKey != "SECRET-1" || s.cfg.Recaptcha.Mode != "v3" {
		t.Fatalf("config tak berubah: %+v", s.cfg.Recaptcha)
	}
	code, m = s.doJSON(t, "GET", "/api/recaptcha/config", nil, "tok-test")
	if code != 200 || m["site_key_set"] != true || m["secret_key_set"] != true {
		t.Fatalf("masking salah: %v", m)
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "SECRET-1") {
		t.Fatalf("secret bocor: %s", raw)
	}
	// tanpa secret_key -> secret lama dipertahankan
	code, _ = s.doJSON(t, "POST", "/api/recaptcha/config", map[string]any{
		"enabled": true, "site_key": "SITE-123", "mode": "v3",
	}, "tok-test")
	if code != 200 || s.cfg.Recaptcha.SecretKey != "SECRET-1" {
		t.Fatalf("secret harus dipertahankan: %+v", s.cfg.Recaptcha)
	}
}

// -- proposed ---------------------------------------------------------------------

func TestProposedApproveReject(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// usulan tak ada -> 404
	code, _ := s.doJSON(t, "POST", "/api/proposed/9999/approve", nil, "tok-test")
	if code != 404 {
		t.Fatalf("harus 404, dapat %d", code)
	}
	code, _ = s.doJSON(t, "POST", "/api/proposed/bukanangka/approve", nil, "tok-test")
	if code != 400 {
		t.Fatalf("bad id harus 400, dapat %d", code)
	}
	// buat usulan langsung via storage
	store := s.d.store
	pid, err := store.ProposeRule(map[string]any{
		"id": "AI-TEST-1", "name": "uji", "category": "anomaly",
		"severity": "high", "pattern": "testpattern123",
	}, "test", "catatan")
	if err != nil {
		t.Fatal(err)
	}
	code, raw := s.do(t, "GET", "/api/proposed", nil, "tok-test")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	var proposed []map[string]any
	if err := json.Unmarshal(raw, &proposed); err != nil {
		t.Fatal(err)
	}
	if len(proposed) != 1 {
		t.Fatalf("diharapkan 1 usulan, dapat %d", len(proposed))
	}
	// approve
	code, m := s.doJSON(t, "POST",
		"/api/proposed/"+strconv.FormatInt(pid, 10)+"/approve", nil, "tok-test")
	if code != 200 {
		t.Fatalf("approve: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["rule_id"] != "AI-TEST-1" {
		t.Fatalf("rule_id=%v", m["rule_id"])
	}
	// rule langsung aktif di engine
	found := false
	for _, r := range s.d.eng.Rules() {
		if r.ID == "AI-TEST-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rule AI-TEST-1 tak aktif di engine")
	}
	// approve lagi -> 404 (sudah tidak pending)
	code, _ = s.doJSON(t, "POST",
		"/api/proposed/"+strconv.FormatInt(pid, 10)+"/approve", nil, "tok-test")
	if code != 404 {
		t.Fatalf("approve ulang harus 404, dapat %d", code)
	}
	// reject
	pid2, err := store.ProposeRule(map[string]any{
		"id": "AI-TEST-2", "pattern": "zzz",
	}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	code, m = s.doJSON(t, "POST",
		"/api/proposed/"+strconv.FormatInt(pid2, 10)+"/reject", nil, "tok-test")
	if code != 200 {
		t.Fatalf("reject: code=%d", code)
	}
	mustOK(t, m)
}

// -- misc GET ---------------------------------------------------------------------

func TestMiscEndpoints(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	for _, p := range []string{
		"/api/requests", "/api/agent-runs", "/api/attack-map",
		"/api/ip-groups", "/api/cf/config",
	} {
		code, _ := s.do(t, "GET", p, nil, "tok-test")
		if code != 200 {
			t.Fatalf("GET %s: code=%d", p, code)
		}
	}
	// /api/cf/zones tanpa token -> 502 (gagal cepat, tanpa network)
	code, m := s.doJSON(t, "GET", "/api/cf/zones", nil, "tok-test")
	if code != 502 || m["error"] == "" {
		t.Fatalf("cf/zones: code=%d body=%v", code, m)
	}
	// /api/cf/stats site tak ada -> 404
	code, _ = s.doJSON(t, "GET", "/api/cf/stats?site_id=takada", nil, "tok-test")
	if code != 404 {
		t.Fatalf("cf/stats site tak ada harus 404, dapat %d", code)
	}
	// /api/* tak dikenal -> 404 JSON
	code, m = s.doJSON(t, "GET", "/api/tidak-ada", nil, "tok-test")
	if code != 404 || m["error"] != "not found" {
		t.Fatalf("unknown api: code=%d body=%v", code, m)
	}
}

// -- SPA ---------------------------------------------------------------------

func TestSPA(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	// halaman utama publik (tanpa token) -> index.html
	code, raw := s.do(t, "GET", "/", nil, "")
	if code != 200 {
		t.Fatalf("GET /: code=%d", code)
	}
	if ct := http.DetectContentType(raw); !strings.Contains(string(raw), `id="app"`) {
		t.Fatalf("index.html tak sesuai: %s / %q", ct, raw[:60])
	}
	// aset statis dengan content-type benar
	code, raw = s.do(t, "GET", "/assets/app.js", nil, "")
	if code != 200 || !strings.Contains(string(raw), "console.log") {
		t.Fatalf("aset: code=%d body=%q", code, raw)
	}
	// route SPA -> fallback index.html
	code, raw = s.do(t, "GET", "/dashboard/setting", nil, "")
	if code != 200 || !strings.Contains(string(raw), `id="app"`) {
		t.Fatalf("fallback SPA: code=%d body=%q", code, raw)
	}
	// traversal tidak boleh lolos: /api/../ -> bukan 200 berisi data API
	code, raw = s.do(t, "GET", "/api/../", nil, "tok-test")
	if code == 200 && strings.Contains(string(raw), "rules_loaded") {
		t.Fatalf("traversal lolos ke API: %q", raw)
	}
	// .. murni -> fallback index.html, bukan file sistem
	code, raw = s.do(t, "GET", "/../../etc/passwd", nil, "")
	if strings.Contains(string(raw), "root:") {
		t.Fatalf("path traversal membaca file sistem!")
	}
}

// -- sertifikat TLS ---------------------------------------------------------------------

// selfSignedPEM membuat pasangan cert/key self-signed untuk test.
func selfSignedPEM(t *testing.T, dnsName string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var cb, kb bytes.Buffer
	if err := pem.Encode(&cb, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	kb2, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&kb, &pem.Block{Type: "PRIVATE KEY", Bytes: kb2}); err != nil {
		t.Fatal(err)
	}
	return cb.String(), kb.String()
}

func TestSiteCertUploadDelete(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	sid := createSite(t, s) // domain: contoh.test

	// validasi: kosong -> 400
	code, _ := s.doJSON(t, "POST", "/api/sites/"+sid+"/cert",
		map[string]any{"cert_pem": "", "key_pem": ""}, "tok-test")
	if code != 400 {
		t.Fatalf("cert kosong harus 400, dapat %d", code)
	}
	// pasangan tak cocok -> 400
	certPEM, _ := selfSignedPEM(t, "contoh.test")
	_, keyPEM2 := selfSignedPEM(t, "lain.test")
	code, m := s.doJSON(t, "POST", "/api/sites/"+sid+"/cert",
		map[string]any{"cert_pem": certPEM, "key_pem": keyPEM2}, "tok-test")
	if code != 400 {
		t.Fatalf("pasangan tak cocok harus 400, dapat %d", code)
	}
	// upload valid
	certPEM2, keyPEM2 := selfSignedPEM(t, "contoh.test")
	code, m = s.doJSON(t, "POST", "/api/sites/"+sid+"/cert",
		map[string]any{"cert_pem": certPEM2, "key_pem": keyPEM2}, "tok-test")
	if code != 200 {
		t.Fatalf("upload: code=%d body=%v", code, m)
	}
	mustOK(t, m)
	if m["domain_match"] != true {
		t.Fatalf("domain_match harus true: %v", m)
	}
	if m["need_restart"] != true || m["tls_active"] != false {
		t.Fatalf("tanpa proxy: tls_active=false need_restart=true: %v", m)
	}
	if m["expires_at"] == float64(0) {
		t.Fatalf("expires_at harus terisi: %v", m)
	}
	if _, ada := m["cert_domains"]; !ada {
		t.Fatalf("cert_domains hilang: %v", m)
	}
	// file tersimpan di dataDir/certs/<id>/
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "certs", sid, "fullchain.pem")); err != nil {
		t.Fatalf("fullchain.pem tak tersimpan: %v", err)
	}
	// hapus
	code, m = s.doJSON(t, "DELETE", "/api/sites/"+sid+"/cert", nil, "tok-test")
	if code != 200 {
		t.Fatalf("delete cert: code=%d", code)
	}
	mustOK(t, m)
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "certs", sid)); !os.IsNotExist(err) {
		t.Fatalf("direktori cert harus terhapus")
	}
	// site tak ada -> 404
	code, _ = s.doJSON(t, "POST", "/api/sites/takada/cert",
		map[string]any{"cert_pem": "x", "key_pem": "y"}, "tok-test")
	if code != 404 {
		t.Fatalf("harus 404, dapat %d", code)
	}
}
