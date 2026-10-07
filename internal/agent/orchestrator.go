// Orkestrator AI agent Perisai WAF. Port dari perisai/agent/orchestrator.py.
//
// Memilih backend (systemone -> llm -> fallback heuristic), menegakkan batas
// kebijakan sehingga agent tidak bisa mengambil keputusan di luar wewenangnya,
// dan mencatat setiap analisis ke storage untuk audit.
package agent

import (
	"fmt"
	"math"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// Verdict adalah keputusan akhir agent atas satu request.
type Verdict struct {
	Decision      string // allow | challenge | block
	Confidence    float64
	Reasoning     []string
	Indicators    []string
	SuggestedRule map[string]any
	Backend       string
	DurationMs    float64
}

// Backend adalah satu backend analisis (systemone, llm, heuristic).
type Backend interface {
	Name() string
	Available() bool
	Analyze(*rules.Request, rules.TriageResult) (Verdict, error)
}

// Jeda sebelum mencoba backend jauh lagi setelah gagal (hindari spam koneksi
// per request). Sama seperti LLM_COOLDOWN / SYSTEMONE_COOLDOWN Python (300 dtk).
const (
	llmCooldown       = 300 * time.Second
	systemoneCooldown = 300 * time.Second
)

// Orchestrator memilih backend, menegakkan kebijakan, dan mencatat audit.
type Orchestrator struct {
	cfg       *config.WAFConfig
	store     *storage.Storage
	heuristic *HeuristicBackend
	llm       *LLMBackend
	systemone *SystemOneBackend
	cooldowns map[string]time.Time
}

// NewOrchestrator membuat orkestrator dari config + storage.
func NewOrchestrator(cfg *config.WAFConfig, store *storage.Storage) *Orchestrator {
	return &Orchestrator{
		cfg:       cfg,
		store:     store,
		heuristic: NewHeuristicBackend(),
		llm:       NewLLMBackend(cfg.Agent.LLM),
		systemone: NewSystemOneBackend(cfg.Agent.SystemOne),
		cooldowns: map[string]time.Time{
			"llm":       time.Time{},
			"systemone": time.Time{},
		},
	}
}

// candidates mengembalikan urutan backend yang dicoba untuk request ini.
//
// auto: systemone (tercepat) -> llm -> heuristic. Mode eksplisit mencoba
// backend pilihannya dulu, lalu heuristic sebagai jaring pengaman. Backend
// yang tidak terkonfigurasi atau sedang cooldown (baru gagal) dilewati.
func (o *Orchestrator) candidates() []Backend {
	mode := o.cfg.Agent.Backend
	now := time.Now()
	s1ok := o.systemone.Available() && !now.Before(o.cooldowns["systemone"])
	llmok := o.llm.Available() && !now.Before(o.cooldowns["llm"])
	var chain []Backend
	switch mode {
	case "llm":
		if llmok {
			chain = append(chain, o.llm)
		}
	case "systemone":
		if s1ok {
			chain = append(chain, o.systemone)
		}
	case "heuristic":
		// hanya heuristic
	default: // auto
		if s1ok {
			chain = append(chain, o.systemone)
		}
		if llmok {
			chain = append(chain, o.llm)
		}
	}
	chain = append(chain, o.heuristic)
	return chain
}

// enforcePolicy menegakkan batas kebijakan atas verdict mentah backend:
//  1. Hit kritis dari engine tidak boleh di-allow oleh agent.
//  2. Verdict allow dengan confidence di bawah min_confidence -> challenge.
//  3. Decision tak dikenal -> challenge; confidence di-clamp 0..1.
func (o *Orchestrator) enforcePolicy(v Verdict, t rules.TriageResult) Verdict {
	reasons := append([]string{}, v.Reasoning...)

	if v.Decision == "allow" {
		for _, h := range t.Hits {
			if h.Severity == "critical" {
				v.Decision = "challenge"
				reasons = append(reasons,
					"Kebijakan: temuan kritis engine tidak boleh di-allow.")
				break
			}
		}
	}
	if v.Decision == "allow" && v.Confidence < o.cfg.Agent.MinConfidence {
		v.Decision = "challenge"
		reasons = append(reasons, fmt.Sprintf(
			"Kebijakan: confidence %.2f di bawah ambang %.2f -> challenge.",
			v.Confidence, o.cfg.Agent.MinConfidence))
	}
	if v.Decision != "allow" && v.Decision != "challenge" && v.Decision != "block" {
		v.Decision = "challenge"
		reasons = append(reasons, "Kebijakan: keputusan tak dikenal -> challenge.")
	}
	v.Confidence = math.Max(0, math.Min(1, v.Confidence))
	v.Reasoning = reasons
	return v
}

// TestLLM menguji koneksi backend LLM (dipakai dashboard & verifikasi 9Router).
func (o *Orchestrator) TestLLM() map[string]any {
	res := o.llm.TestConnection()
	res["backend"] = "llm"
	res["base_url"] = o.cfg.Agent.LLM.BaseURL
	return res
}

// TestSystemOne menguji koneksi backend System One (dipakai dashboard).
func (o *Orchestrator) TestSystemOne() map[string]any {
	res := o.systemone.TestConnection()
	res["backend"] = "systemone"
	res["endpoint"] = o.cfg.Agent.SystemOne.Endpoint
	return res
}

// Analyze menjalankan satu backend (sesuai urutan kandidat) dan menegakkan
// kebijakan atas hasilnya. Setiap analisis dicatat ke storage untuk audit.
func (o *Orchestrator) Analyze(r *rules.Request, t rules.TriageResult) (Verdict, error) {
	start := time.Now()
	var tried []string
	var verdict *Verdict
	var lastErr error
	for _, be := range o.candidates() {
		name := be.Name()
		tried = append(tried, name)
		if name == "systemone" {
			// Ambang selalu ikut setting terbaru (berlaku langsung).
			o.systemone.MinConfidence = o.cfg.Agent.MinConfidence
		}
		v, err := be.Analyze(r, t)
		if err != nil {
			// Backend jauh down/timeout -> cooldown + lanjut ke berikut.
			lastErr = err
			if _, ok := o.cooldowns[name]; ok {
				cd := llmCooldown
				if name == "systemone" {
					cd = systemoneCooldown
				}
				o.cooldowns[name] = time.Now().Add(cd)
			}
			continue
		}
		vv := v
		verdict = &vv
		break
	}
	if verdict == nil {
		// Hanya terjadi bila heuristic sendiri yang gagal.
		return Verdict{}, lastErr
	}
	if verdict.Backend == "heuristic" && len(tried) > 0 && tried[0] != "heuristic" {
		verdict.Reasoning = append(verdict.Reasoning,
			"Fallback: backend "+tried[0]+" tidak terjangkau.")
	}

	v := o.enforcePolicy(*verdict, t)
	v.DurationMs = roundHalfEven(time.Since(start).Seconds()*1000, 1)
	if err := o.logRun(r, v); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

// logRun mencatat satu analisis agent ke storage.
func (o *Orchestrator) logRun(r *rules.Request, v Verdict) error {
	reasoning := make([]any, len(v.Reasoning))
	for i, s := range v.Reasoning {
		reasoning[i] = s
	}
	indicators := make([]any, len(v.Indicators))
	for i, s := range v.Indicators {
		indicators[i] = s
	}
	_, err := o.store.LogAgentRun(r.ID, v.Backend, v.Decision, v.Confidence,
		reasoning, indicators, v.DurationMs)
	return err
}
