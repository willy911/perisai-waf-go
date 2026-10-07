package learner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// newStore membuat storage SQLite di direktori sementara.
func newStore(t *testing.T) *storage.Storage {
	t.Helper()
	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// cfgLearn membuat LearningConfig uji.
func cfgLearn(enabled, autoApprove bool, minConf float64) config.LearningConfig {
	return config.LearningConfig{
		Enabled:       enabled,
		AutoApprove:   autoApprove,
		MinConfidence: minConf,
	}
}

// verdictRule membuat verdict seperti yang dihasilkan HeuristicBackend:
// decision block + suggested_rule bentuk {"id","name","category",
// "severity","pattern"} (vektor dari tests/test_agent.py Python).
func verdictRule(conf float64) agent.Verdict {
	return agent.Verdict{
		Decision:   "block",
		Confidence: conf,
		Backend:    "heuristic",
		Reasoning:  []string{"Mengusulkan signature baru dari keyword dominan."},
		Indicators: []string{"evasion: percent-encoding"},
		SuggestedRule: map[string]any{
			"id":       "AI-XSS-AUTO",
			"name":     "AI-learned: <script>",
			"category": "xss",
			"severity": "high",
			"pattern":  `<script>alert\(1\)</script>`,
		},
	}
}

// pendingCount menghitung usulan berstatus "pending".
func pendingCount(t *testing.T, st *storage.Storage) int {
	t.Helper()
	items, err := st.ListProposed("pending")
	if err != nil {
		t.Fatalf("ListProposed: %v", err)
	}
	return len(items)
}

// -- learning dinonaktifkan: tidak ada usulan --------------------------------

func TestDisabledNoProposal(t *testing.T) {
	st := newStore(t)
	MaybeLearn(st, cfgLearn(false, false, 0.85), verdictRule(0.95), rules.TriageResult{})
	if n := pendingCount(t, st); n != 0 {
		t.Fatalf("learning disabled: usulan tercatat = %d, mau 0", n)
	}
}

// -- verdict tanpa suggested_rule: tidak ada usulan --------------------------

func TestNilSuggestedRuleNoProposal(t *testing.T) {
	st := newStore(t)
	v := verdictRule(0.95)
	v.SuggestedRule = nil
	MaybeLearn(st, cfgLearn(true, false, 0.85), v, rules.TriageResult{})
	if n := pendingCount(t, st); n != 0 {
		t.Fatalf("suggested_rule nil: usulan tercatat = %d, mau 0", n)
	}
}

// -- confidence di bawah ambang: tidak ada usulan ----------------------------

func TestLowConfidenceNoProposal(t *testing.T) {
	st := newStore(t)
	MaybeLearn(st, cfgLearn(true, false, 0.85), verdictRule(0.60), rules.TriageResult{})
	if n := pendingCount(t, st); n != 0 {
		t.Fatalf("confidence 0.60 < 0.85: usulan tercatat = %d, mau 0", n)
	}
}

// -- confidence cukup: usulan tercatat ---------------------------------------

func TestProposeWhenConfident(t *testing.T) {
	st := newStore(t)
	MaybeLearn(st, cfgLearn(true, false, 0.85), verdictRule(0.90), rules.TriageResult{})

	items, err := st.ListProposed("pending")
	if err != nil {
		t.Fatalf("ListProposed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("usulan pending = %d, mau 1", len(items))
	}
	it := items[0]
	if it["source"] != "ai-agent" {
		t.Fatalf("source = %v, mau ai-agent", it["source"])
	}
	if it["note"] != "confidence=0.90 backend=heuristic" {
		t.Fatalf("note = %q, mau confidence=0.90 backend=heuristic", it["note"])
	}
	rule, ok := it["rule"].(map[string]any)
	if !ok {
		t.Fatalf("rule bukan map: %T", it["rule"])
	}
	for _, k := range []string{"id", "name", "category", "severity", "pattern"} {
		if _, ok := rule[k]; !ok {
			t.Fatalf("rule kehilangan key %q: %v", k, rule)
		}
	}
	if rule["id"] != "AI-XSS-AUTO" || rule["pattern"] != `<script>alert\(1\)</script>` {
		t.Fatalf("rule tidak sesuai: %v", rule)
	}
	// custom_rules.json belum tersentuh (auto_approve mati)
	custom, err := st.ListCustomRules()
	if err != nil {
		t.Fatalf("ListCustomRules: %v", err)
	}
	if len(custom) != 0 {
		t.Fatalf("custom rules = %d, mau 0 (belum approve)", len(custom))
	}
}

// -- default severity/category bila agent tidak mengisinya -------------------

func TestDefaultSeverityCategory(t *testing.T) {
	st := newStore(t)
	v := verdictRule(0.90)
	delete(v.SuggestedRule, "severity")
	delete(v.SuggestedRule, "category")
	MaybeLearn(st, cfgLearn(true, false, 0.85), v, rules.TriageResult{})

	items, err := st.ListProposed("pending")
	if err != nil || len(items) != 1 {
		t.Fatalf("ListProposed: %v, %d", err, len(items))
	}
	rule := items[0]["rule"].(map[string]any)
	if rule["severity"] != "high" || rule["category"] != "anomaly" {
		t.Fatalf("default tidak diterapkan: %v", rule)
	}
}

// -- pattern tidak valid: tidak ada usulan -----------------------------------

func TestInvalidPatternNoProposal(t *testing.T) {
	st := newStore(t)
	v := verdictRule(0.95)
	v.SuggestedRule["pattern"] = `([a-z` // regex rusak
	MaybeLearn(st, cfgLearn(true, false, 0.85), v, rules.TriageResult{})
	if n := pendingCount(t, st); n != 0 {
		t.Fatalf("pattern rusak: usulan tercatat = %d, mau 0", n)
	}
}

// -- auto_approve: rule aktif di custom_rules.json + usulan approved -----------

func TestAutoApproveActivatesRule(t *testing.T) {
	dir := t.TempDir()
	st, err := storage.New(dir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	MaybeLearn(st, cfgLearn(true, true, 0.85), verdictRule(0.92), rules.TriageResult{})

	// custom_rules.json berisi 1 rule valid
	path := filepath.Join(dir, "custom_rules.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("custom_rules.json tidak dibuat: %v", err)
	}
	var custom []map[string]any
	if err := json.Unmarshal(data, &custom); err != nil {
		t.Fatalf("custom_rules.json rusak: %v", err)
	}
	if len(custom) != 1 {
		t.Fatalf("rule di custom_rules.json = %d, mau 1", len(custom))
	}
	r := custom[0]
	if r["id"] != "AI-XSS-AUTO" || r["severity"] != "high" {
		t.Fatalf("rule tidak sesuai: %v", r)
	}
	// pattern yang tersimpan harus bisa dikompilasi & cocok dengan serangan
	re, err := regexp.Compile("(?is)" + r["pattern"].(string))
	if err != nil {
		t.Fatalf("pattern tersimpan tidak bisa dikompilasi: %v", err)
	}
	if !re.MatchString("<script>alert(1)</script>") {
		t.Fatal("pattern tersimpan tidak cocok dengan payload serangan")
	}

	// usulan berstatus approved, tidak ada lagi yang pending
	if n := pendingCount(t, st); n != 0 {
		t.Fatalf("usulan pending = %d, mau 0", n)
	}
	approved, err := st.ListProposed("approved")
	if err != nil {
		t.Fatalf("ListProposed(approved): %v", err)
	}
	if len(approved) != 1 {
		t.Fatalf("usulan approved = %d, mau 1", len(approved))
	}

	// storage.ListCustomRules (dipakai dashboard) melihat rule yang sama
	via, err := st.ListCustomRules()
	if err != nil {
		t.Fatalf("ListCustomRules: %v", err)
	}
	if len(via) != 1 || via[0]["id"] != "AI-XSS-AUTO" {
		t.Fatalf("ListCustomRules tidak sinkron: %v", via)
	}
}

// -- auto_approve tidak menduplikasi id rule yang sudah ada -------------------

func TestAutoApproveNoDuplicate(t *testing.T) {
	st := newStore(t)
	cfg := cfgLearn(true, true, 0.85)
	MaybeLearn(st, cfg, verdictRule(0.92), rules.TriageResult{})
	MaybeLearn(st, cfg, verdictRule(0.93), rules.TriageResult{}) // id sama

	custom, err := st.ListCustomRules()
	if err != nil {
		t.Fatalf("ListCustomRules: %v", err)
	}
	if len(custom) != 1 {
		t.Fatalf("custom rules = %d, mau 1 (tanpa duplikat)", len(custom))
	}
	approved, err := st.ListProposed("approved")
	if err != nil {
		t.Fatalf("ListProposed(approved): %v", err)
	}
	if len(approved) != 2 {
		t.Fatalf("usulan approved = %d, mau 2", len(approved))
	}
}
