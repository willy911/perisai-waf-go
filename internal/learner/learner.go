// Package learner mengubah verdict AI agent menjadi usulan signature baru.
// Port dari perisai/learner.py (Python).
//
// Alur: agent.Verdict membawa SuggestedRule -> disimpan sebagai "pending"
// via storage.ProposeRule -> admin menyetujui via dashboard (atau otomatis
// bila auto_approve) -> aturan aktif di dataDir/custom_rules.json dan
// dibaca engine lewat storage.ListCustomRules.
package learner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// MaybeLearn mempelajari verdict agent: bila learning.enabled mati atau
// verdict tidak membawa suggested_rule, tidak terjadi apa-apa. Bila
// suggested_rule ada dan confidence memenuhi learning.min_confidence,
// usulan disimpan (status "pending") dengan source "ai-agent". Bila
// learning.auto_approve aktif, usulan langsung diaktifkan sebagai custom
// rule di dataDir/custom_rules.json dan ditandai "approved".
//
// Penyimpangan dari Python: di Python usulan SELALU disimpan (bila enabled
// dan ada suggested_rule), dan auto_approve hanya jalan bila confidence >=
// min_confidence. Di sini sesuai kontrak port, pengusulan sendiri sudah
// mensyaratkan confidence >= min_confidence.
func MaybeLearn(store *storage.Storage, cfg config.LearningConfig, verdict agent.Verdict, triage rules.TriageResult) {
	_ = triage // triase hanya konteks; keputusan belajar murni dari verdict.
	if !cfg.Enabled || verdict.SuggestedRule == nil {
		return
	}
	rule := normalizeRule(verdict.SuggestedRule)
	if rule == nil {
		return // pattern tidak bisa dikompilasi
	}
	if verdict.Confidence < cfg.MinConfidence {
		return
	}
	note := fmt.Sprintf("confidence=%.2f backend=%s", verdict.Confidence, verdict.Backend)
	pid, err := store.ProposeRule(rule, "ai-agent", note)
	if err != nil {
		return
	}
	if cfg.AutoApprove {
		approve(store, pid, rule)
	}
}

// normalizeRule menyalin suggested_rule agent ke bentuk kanonis
// {"id","name","category","severity","pattern"} seperti learner.py Python,
// dengan default severity="high" dan category="anomaly". Mengembalikan nil
// bila pattern kosong atau tidak bisa dikompilasi case-insensitive + dotall
// (setara re.IGNORECASE|re.DOTALL di Python).
func normalizeRule(sr map[string]any) map[string]any {
	pattern := toStr(sr["pattern"])
	if pattern == "" {
		return nil
	}
	if _, err := regexp.Compile("(?is)" + pattern); err != nil {
		return nil
	}
	id := toStr(sr["id"])
	if id == "" {
		id = "AI-UNKNOWN"
	}
	name := toStr(sr["name"])
	if name == "" {
		name = id
	}
	category := toStr(sr["category"])
	if category == "" {
		category = "anomaly"
	}
	severity := toStr(sr["severity"])
	if severity == "" {
		severity = "high"
	}
	return map[string]any{
		"id":       id,
		"name":     name,
		"category": category,
		"severity": severity,
		"pattern":  pattern,
	}
}

// approve mengaktifkan usulan: append ke dataDir/custom_rules.json bila id
// rule belum ada di sana (hindari duplikat, seperti learner.py), lalu tandai
// usulan sebagai "approved". Bila file belum ada, file dibuat baru.
func approve(store *storage.Storage, pid int64, rule map[string]any) {
	path := filepath.Join(store.DataDir(), "custom_rules.json")
	custom := readCustom(path)
	found := false
	for _, r := range custom {
		if toStr(r["id"]) == toStr(rule["id"]) {
			found = true
			break
		}
	}
	if !found {
		custom = append(custom, rule)
		if err := writeCustom(path, custom); err != nil {
			return
		}
	}
	_ = store.SetProposedStatus(pid, "approved")
}

// readCustom membaca array JSON custom_rules.json; file hilang atau rusak ->
// slice kosong (seperti _read_custom di Python).
func readCustom(path string) []map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return []map[string]any{}
	}
	var out []map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return []map[string]any{}
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// writeCustom menulis array rule ke custom_rules.json (indent 2, seperti
// _write_custom di Python).
func writeCustom(path string, custom []map[string]any) error {
	data, err := json.MarshalIndent(custom, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// toStr mengubah nilai map menjadi string (nilai non-string di-Sprint).
func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// Approve mengaktifkan satu usulan "pending": sama seperti approve() internal,
// tapi mencari dulu usulan berdasar pid. Mengembalikan map rule kanonis dan
// true bila usulan ditemukan (dipakai dashboard untuk mengaktifkan rule di
// engine yang sedang berjalan). Setara Learner.approve di learner.py.
func Approve(store *storage.Storage, pid int64) (map[string]any, bool, error) {
	pending, err := store.ListProposed("pending")
	if err != nil {
		return nil, false, err
	}
	for _, p := range pending {
		id, _ := toInt64(p["id"])
		if id != pid {
			continue
		}
		rule, _ := p["rule"].(map[string]any)
		if rule == nil {
			rule = map[string]any{}
		}
		approve(store, pid, rule)
		return rule, true, nil
	}
	return nil, false, nil
}

// Reject menolak satu usulan (status -> "rejected").
// Setara Learner.reject di learner.py.
func Reject(store *storage.Storage, pid int64) error {
	return store.SetProposedStatus(pid, "rejected")
}

// ToRule mengubah map rule kanonis {id,name,category,severity,pattern}
// menjadi rules.Rule siap dipakai engine. Setara Learner._to_rule di
// learner.py (pattern dikompilasi case-insensitive + dotall).
func ToRule(d map[string]any) (rules.Rule, error) {
	pattern := toStr(d["pattern"])
	re, err := regexp.Compile("(?is)" + pattern)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("pattern tidak valid: %w", err)
	}
	id := toStr(d["id"])
	if id == "" {
		id = "AI-UNKNOWN"
	}
	name := toStr(d["name"])
	if name == "" {
		name = id
	}
	category := toStr(d["category"])
	if category == "" {
		category = "anomaly"
	}
	severity := toStr(d["severity"])
	if severity == "" {
		severity = "high"
	}
	return rules.Rule{
		ID:       id,
		Name:     name,
		Category: category,
		Severity: severity,
		Patterns: []*regexp.Regexp{re},
		Weight:   rules.SeverityWeight(severity),
	}, nil
}

// toInt64 mengambil nilai integer dari map storage (kolom INTEGER SQLite).
func toInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	default:
		return 0, false
	}
}
