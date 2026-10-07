// Backend System One: keputusan cepat non-autoregresif via protokol /v1/systemone.
// Port dari perisai/agent/systemone.py.
//
// Berbeda dengan backend LLM yang men-generate teks token-per-token, System One
// menjawab pertanyaan bertipe (Noul/Choice/Score) dalam SATU forward pass dan
// mengembalikan probabilitas terkalibrasi yang bisa langsung dikonsumsi kode.
//
// Untuk triase trafik abu-abu WAF, backend ini menanyakan satu pertanyaan Noul
// “is_attack“: probabilitas bahwa request adalah serangan web. Pemetaan:
//
//	p >= 0.85            -> block
//	p >= min_confidence  -> challenge
//	p <  min_confidence  -> allow (confidence = 1 - p)
//
// Bila jawaban membawa “noul_raw“ (posterior terkalibrasi sebelum aturan
// band), nilai itu yang dipakai untuk gating; bila tidak ada, pakai “noul“.
//
// CATATAN PRIVASI: ringkasan request (maks 4KB body + header terredaksi,
// tanpa cookie/authorization) dikirim ke endpoint System One. Untuk data
// sensitif, self-host implementasi open-source protokol ini atau pakai
// backend 'heuristic'.
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
)

// BlockP adalah ambang probabilitas serangan untuk block langsung. Di bawah
// ini (tapi di atas min_confidence) -> challenge; jauh di bawah -> allow.
const BlockP = 0.85

// QuestionIsAttack adalah pertanyaan Noul is_attack; instructions + criteria
// disalin PERSIS dari perisai/agent/systemone.py.
var QuestionIsAttack = map[string]any{
	"type":         "noul",
	"instructions": "Is this HTTP request a web attack (SQL injection, XSS, RCE, LFI, SSRF, CVE exploit, scanner/probe, webshell upload) rather than legitimate user traffic?",
	"criteria": map[string]any{
		"true":  "The request shows attack intent: injection payloads, encoded/obfuscated malicious patterns, exploit probes, or scanner behavior.",
		"false": "Normal user traffic: page browsing, forms, API calls without malicious payloads.",
	},
}

// extractError mengambil pesan error dari respons API (format {"error": "..."}).
func extractError(data map[string]any, statusCode int) string {
	if data != nil {
		if e, ok := data["error"].(string); ok && e != "" {
			return potongRune(e, 300)
		}
	}
	return fmt.Sprintf("HTTP %d", statusCode)
}

// ParseNoul mengambil P(true) dari jawaban Noul.
//
// Urutan: noul_raw (posterior terkalibrasi, sinyal gating terbaik) ->
// noul -> probability/p (varian lain). Mengembalikan error bila tak ada.
func ParseNoul(answer map[string]any) (float64, error) {
	if answer == nil {
		return 0, fmt.Errorf("jawaban noul bukan object")
	}
	for _, key := range []string{"noul_raw", "noul", "probability", "p"} {
		val, ok := answer[key]
		if !ok || val == nil {
			continue
		}
		if _, isBool := val.(bool); isBool {
			continue
		}
		var f float64
		switch v := val.(type) {
		case float64:
			f = v
		case float32:
			f = float64(v)
		case int:
			f = float64(v)
		case int64:
			f = float64(v)
		case json.Number:
			n, err := v.Float64()
			if err != nil {
				continue
			}
			f = n
		default:
			continue
		}
		if f < 0 {
			f = 0
		}
		if f > 1 {
			f = 1
		}
		return f, nil
	}
	return 0, fmt.Errorf("jawaban noul tidak mengandung probabilitas")
}

// SystemOneBackend menanyakan probabilitas serangan ke endpoint /v1/systemone.
type SystemOneBackend struct {
	cfg           config.SystemOneConfig
	MinConfidence float64 // selalu di-sync orkestrator dari config terbaru
	lastLatencyMs float64
}

// NewSystemOneBackend membuat backend System One (default min_confidence 0.55
// seperti Python; orkestrator menimpanya tiap Analyze).
func NewSystemOneBackend(cfg config.SystemOneConfig) *SystemOneBackend {
	return &SystemOneBackend{cfg: cfg, MinConfidence: 0.55}
}

// Name mengembalikan nama backend untuk interface Backend.
func (b *SystemOneBackend) Name() string { return "systemone" }

// Available true bila enabled dan endpoint terisi (seperti Python).
func (b *SystemOneBackend) Available() bool {
	return b.cfg.Enabled && b.cfg.Endpoint != ""
}

// Query mengirim satu request /v1/systemone, mengembalikan dict “answers“.
//
// Mengembalikan error bila HTTP error / format respons tak dikenal.
func (b *SystemOneBackend) Query(state any, questions map[string]any, timeoutSec int) (map[string]any, error) {
	if timeoutSec <= 0 {
		timeoutSec = b.cfg.Timeout
	}
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	payload := map[string]any{
		"model":     b.cfg.Model,
		"state":     state,
		"questions": questions,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, b.cfg.Endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("tidak bisa menghubungi System One: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if b.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+b.cfg.APIKey)
	}
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tidak bisa menghubungi System One: %w", err)
	}
	defer resp.Body.Close()
	b.lastLatencyMs = roundHalfEven(time.Since(t0).Seconds()*1000, 1)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("tidak bisa menghubungi System One: %w", err)
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("respons System One bukan JSON (%s): %w",
			extractError(nil, resp.StatusCode), err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("System One error: %s", extractError(data, resp.StatusCode))
	}
	answers, ok := data["answers"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("respons /v1/systemone tanpa field 'answers'")
	}
	return answers, nil
}

// TestConnection mengecek cepat: satu pertanyaan Noul ringan ke endpoint.
func (b *SystemOneBackend) TestConnection() map[string]any {
	answers, err := b.Query("ping", map[string]any{
		"ping": map[string]any{
			"type":         "noul",
			"instructions": "Is this message a harmless connectivity test?",
		},
	}, 10)
	if err != nil {
		return map[string]any{"ok": false, "model": b.cfg.Model,
			"error": potongRune(err.Error(), 300)}
	}
	p, err := ParseNoul(toStringMap(answers["ping"]))
	if err != nil {
		return map[string]any{"ok": false, "model": b.cfg.Model,
			"error": potongRune(err.Error(), 300)}
	}
	return map[string]any{"ok": true, "model": b.cfg.Model,
		"latency_ms": b.lastLatencyMs,
		"p_test":     roundHalfEven(p, 3)}
}

// Analyze menanyakan P(serangan) lalu memetakannya ke block/challenge/allow.
func (b *SystemOneBackend) Analyze(r *rules.Request, t rules.TriageResult) (Verdict, error) {
	state := BuildContext(r, t)
	answers, err := b.Query(state, map[string]any{"is_attack": QuestionIsAttack}, 0)
	if err != nil {
		return Verdict{}, err
	}
	p, err := ParseNoul(toStringMap(answers["is_attack"]))
	if err != nil {
		return Verdict{}, err
	}

	mc := b.MinConfidence
	var decision string
	var confidence float64
	var why string
	if p >= BlockP {
		decision, confidence = "block", p
		why = fmt.Sprintf("P(serangan)=%.2f >= %.2f -> block", p, BlockP)
	} else if p >= mc {
		decision, confidence = "challenge", p
		why = fmt.Sprintf("P(serangan)=%.2f di atas ambang %.2f tapi di bawah %.2f -> challenge",
			p, mc, BlockP)
	} else {
		decision, confidence = "allow", 1.0-p
		why = fmt.Sprintf("P(serangan)=%.2f di bawah ambang %.2f -> allow", p, mc)
	}

	reasoning := []string{
		fmt.Sprintf("System One (%s): %s (%v ms).", b.cfg.Model, why, b.lastLatencyMs),
		fmt.Sprintf("Skor rules engine: %v; temuan: %d.", t.Score, len(t.Hits)),
	}
	indicators := []string{fmt.Sprintf("systemone:is_attack=%.2f", p)}
	for i, h := range t.Hits {
		if i >= 6 {
			break
		}
		indicators = append(indicators, h.Category+":"+h.RuleID)
	}

	return Verdict{
		Decision:      decision,
		Confidence:    confidence,
		Reasoning:     reasoning,
		Indicators:    indicators,
		SuggestedRule: nil,
		Backend:       "systemone",
	}, nil
}

// toStringMap mengkonversi any ke map[string]any bila memungkinkan.
func toStringMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
