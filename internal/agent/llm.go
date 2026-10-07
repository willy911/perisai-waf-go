// Backend LLM via API OpenAI-compatible (Ollama lokal, 9Router, OpenAI, dsb).
// Port dari perisai/agent/llm.py.
//
// Agent diberi konteks request yang sudah diringkas + hasil rules engine,
// lalu diminta mengembalikan JSON ketat: decision, confidence, reasoning,
// indicators, dan optional suggested_rule.
//
// CATATAN PRIVASI: cuplikan body (maks 4KB) dan header terredaksi dikirim ke
// endpoint LLM. Untuk data sensitif, gunakan backend 'heuristic' atau LLM
// yang jalan lokal (Ollama).
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
)

// SystemPrompt adalah system prompt analis WAF, disalin PERSIS byte-per-byte
// dari perisai/agent/llm.py (dijaga oleh TestSystemPromptByteIdentical).
const SystemPrompt = `Kamu adalah analis keamanan Web Application Firewall (WAF).
Tugasmu: menilai SATU HTTP request apakah serangan atau trafik normal.

Keputusan:
- "allow": trafik normal / kemungkinan besar aman.
- "challenge": mencurigakan tapi belum jelas (minta verifikasi JS cookie).
- "block": jelas serangan (SQLi, XSS, RCE, LFI, SSRF, exploit CVE, scanner).

Aturan:
- Fokus pada NIAT request, bukan sekadar keyword.
- Teknik obfuskasi (encoding ganda, unicode, base64, mixed-case) = sinyal jahat.
- Parameter normal (nama, alamat, teks) yang mengandung kata umum BUKAN serangan.
- Jika ada hit "critical" dari rules engine, JANGAN pernah jawab "allow".

Balas HANYA dengan JSON valid, tanpa markdown:
{"decision": "allow|challenge|block",
 "confidence": 0.0-1.0,
 "reasoning": ["poin analisis 1", "poin 2"],
 "indicators": ["kategori:indikator"],
 "suggested_rule": {"id": "...", "name": "...", "category": "...",
   "severity": "high", "pattern": "regex"} atau null}
`

var jsonRe = regexp.MustCompile(`(?s)\{.*\}`)

// headerSensitif adalah header yang nilainya disamarkan sebelum dikirim
// ke endpoint LLM (authorization/cookie tidak boleh bocor).
var headerSensitif = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
}

// FetchModels mengambil daftar model dari endpoint OpenAI-compatible
// (GET {base}/models). Mengembalikan list [{"id","owned_by"}] terurut.
// Timeout default 15 detik, seperti Python.
func FetchModels(baseURL, apiKey string) ([]map[string]string, error) {
	url := strings.TrimRight(baseURL, "/") + "/models"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("tidak bisa mengambil daftar model: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tidak bisa mengambil daftar model: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("tidak bisa mengambil daftar model: HTTP %d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("tidak bisa mengambil daftar model: %w", err)
	}
	items, ok := data["data"].([]any)
	if !ok {
		return nil, fmt.Errorf("respons /models bukan format OpenAI (tanpa field 'data')")
	}
	models := make([]map[string]string, 0, len(items))
	for _, m := range items {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		id, _ := mm["id"].(string)
		if id == "" {
			continue
		}
		owned, _ := mm["owned_by"].(string)
		models = append(models, map[string]string{"id": id, "owned_by": owned})
	}
	sort.Slice(models, func(i, j int) bool {
		return strings.ToLower(models[i]["id"]) < strings.ToLower(models[j]["id"])
	})
	return models, nil
}

// redactHeaders menyamarkan header sensitif; nilai lain dipangkas 300 char.
func redactHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		kl := strings.ToLower(k)
		if headerSensitif[kl] {
			out[kl] = fmt.Sprintf("<redacted %d chars>", len([]rune(v)))
		} else {
			out[kl] = potongRune(v, 300)
		}
	}
	return out
}

// BuildContext membangun ringkasan request + hasil engine untuk LLM / System One.
// Body dibatasi 4KB (latin-1), header sensitif disamarkan.
func BuildContext(r *rules.Request, t rules.TriageResult) map[string]any {
	body := r.Body
	if len(body) > 4096 {
		body = body[:4096]
	}
	br := make([]rune, len(body))
	for i, c := range body {
		br[i] = rune(c)
	}
	hits := make([]map[string]any, 0, len(t.Hits))
	for _, h := range t.Hits {
		hits = append(hits, map[string]any{
			"rule_id":  h.RuleID,
			"name":     h.Name,
			"category": h.Category,
			"severity": h.Severity,
			"evidence": h.Evidence,
			"location": h.Location,
		})
	}
	return map[string]any{
		"method":         r.Method,
		"path":           potongRune(r.Path, 500),
		"query":          potongRune(r.Query, 1000),
		"headers":        redactHeaders(r.Headers),
		"body_excerpt":   string(br),
		"client_ip":      r.ClientIP,
		"engine_score":   t.Score,
		"engine_hits":    hits,
		"engine_reasons": t.Reasons,
	}
}

// LLMBackend memanggil endpoint chat/completions yang OpenAI-compatible.
type LLMBackend struct {
	cfg         config.LLMConfig
	lastLatency float64
}

// NewLLMBackend membuat backend LLM dari config.
func NewLLMBackend(cfg config.LLMConfig) *LLMBackend {
	return &LLMBackend{cfg: cfg}
}

// Name mengembalikan nama backend untuk interface Backend.
func (b *LLMBackend) Name() string { return "llm" }

// Available true bila base_url terisi (seperti Python).
func (b *LLMBackend) Available() bool { return b.cfg.BaseURL != "" }

// post mengirim chat completion dan mengembalikan isi content mentah.
func (b *LLMBackend) post(messages []map[string]string, maxTokens int, timeoutSec int) (string, error) {
	if timeoutSec <= 0 {
		timeoutSec = b.cfg.Timeout
	}
	if timeoutSec <= 0 {
		timeoutSec = 20
	}
	payload := map[string]any{
		"model":       b.cfg.Model,
		"messages":    messages,
		"temperature": 0.1,
		"max_tokens":  maxTokens,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	url := strings.TrimRight(b.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+b.cfg.APIKey)
	}
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b.lastLatency = roundHalfEven(time.Since(t0).Seconds()*1000, 1)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, potongRune(strings.TrimSpace(string(body)), 300))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("respons LLM bukan JSON: %w", err)
	}
	choices, _ := data["choices"].([]any)
	if len(choices) == 0 {
		return "", fmt.Errorf("respons LLM tanpa choices")
	}
	first, _ := choices[0].(map[string]any)
	msg, _ := first["message"].(map[string]any)
	content, _ := msg["content"].(string)
	return content, nil
}

// TestConnection mengecek cepat apakah endpoint (mis. 9Router) hidup &
// API key valid.
func (b *LLMBackend) TestConnection() map[string]any {
	content, err := b.post(
		[]map[string]string{{"role": "user", "content": "Balas hanya dengan kata: ok"}},
		10, 10,
	)
	if err != nil {
		return map[string]any{"ok": false, "model": b.cfg.Model,
			"error": potongRune(err.Error(), 300)}
	}
	return map[string]any{"ok": true, "model": b.cfg.Model,
		"latency_ms": b.lastLatency,
		"reply":      potongRune(strings.TrimSpace(content), 100)}
}

// Analyze meminta verdict JSON dari LLM lalu mem-parsenya.
func (b *LLMBackend) Analyze(r *rules.Request, t rules.TriageResult) (Verdict, error) {
	ctx := BuildContext(r, t)
	ctxRaw, err := json.Marshal(ctx)
	if err != nil {
		return Verdict{}, err
	}
	content, err := b.post([]map[string]string{
		{"role": "system", "content": SystemPrompt},
		{"role": "user", "content": string(ctxRaw)},
	}, 800, 0)
	if err != nil {
		return Verdict{}, err
	}
	m := jsonRe.FindString(content)
	if m == "" {
		return Verdict{}, fmt.Errorf("LLM tidak mengembalikan JSON")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(m), &parsed); err != nil {
		return Verdict{}, fmt.Errorf("LLM tidak mengembalikan JSON: %w", err)
	}

	decision, _ := parsed["decision"].(string)
	decision = strings.ToLower(strings.TrimSpace(decision))
	if decision != "allow" && decision != "challenge" && decision != "block" {
		decision = "challenge"
	}
	confidence := 0.5
	if c, ok := parsed["confidence"].(float64); ok {
		confidence = c
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}
	var reasoning []string
	if rs, ok := parsed["reasoning"].([]any); ok {
		for _, x := range rs {
			reasoning = append(reasoning, fmt.Sprint(x))
			if len(reasoning) >= 8 {
				break
			}
		}
	}
	var indicators []string
	if is, ok := parsed["indicators"].([]any); ok {
		for _, x := range is {
			indicators = append(indicators, fmt.Sprint(x))
			if len(indicators) >= 12 {
				break
			}
		}
	}
	var suggested map[string]any
	if s, ok := parsed["suggested_rule"].(map[string]any); ok {
		suggested = s
	}

	return Verdict{
		Decision:      decision,
		Confidence:    confidence,
		Reasoning:     reasoning,
		Indicators:    indicators,
		SuggestedRule: suggested,
		Backend:       "llm",
	}, nil
}
