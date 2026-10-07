// Package rules berisi signature pack bawaan + rules engine triase skor
// Perisai WAF. Port dari perisai/rules/signatures.py dan perisai/engine.py.
//
// Setiap request dipindai signature di 3 zona (path, header, body), versi
// mentah DAN versi ter-decode (multi url-decode, lawan obfuskasi).
// Skor total menentukan jalur: allow | agent (abu-abu) | block.
package rules

import (
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/willy911/perisai-waf/internal/config"
)

// scanLimit membatasi panjang tiap zona pemindaian (cegah ReDoS mahal pada
// body raksasa). Sama seperti SCAN_LIMIT Python (32 KiB).
const scanLimit = 32 * 1024

// Hit adalah satu rule yang cocok pada sebuah request.
type Hit struct {
	RuleID   string
	Name     string
	Category string
	Severity string
	Evidence string
	Location string // path | header | body
	Weight   float64
}

// Request adalah representasi request HTTP yang dipindai engine.
type Request struct {
	ID       string
	Method   string
	Path     string
	Query    string
	Headers  map[string]string
	Body     []byte
	ClientIP string
}

// TriageResult adalah hasil triase satu request.
type TriageResult struct {
	Score   float64
	Action  string // allow|agent|block
	Hits    []Hit
	Reasons []string
}

// Engine memindai request terhadap signature bawaan + custom rule.
// Aman dipakai dari banyak goroutine (daftar rule dikunci sendiri).
type Engine struct {
	cfg   *config.WAFConfig
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine membuat engine dengan rule bawaan ditambah customRules
// (pola regex dari storage/learner). Setara Engine.__init__ + add_custom_rules.
func NewEngine(cfg *config.WAFConfig, customRules []Rule) *Engine {
	rules := make([]Rule, 0, len(builtinRules)+len(customRules))
	rules = append(rules, builtinRules...)
	rules = append(rules, customRules...)
	return &Engine{cfg: cfg, rules: rules}
}

// Rules mengembalikan salinan seluruh rule aktif (bawaan + custom).
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// AddCustomRules menambahkan custom rule ke engine yang sedang berjalan
// (mis. hasil approve usulan learner di dashboard). Setara
// add_custom_rules di engine Python.
func (e *Engine) AddCustomRules(custom []Rule) {
	if len(custom) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, custom...)
}

// SeverityWeight mengembalikan bobot skor untuk severity
// (critical|high|medium|low); dipakai saat membangun Rule dari usulan learner.
func SeverityWeight(severity string) float64 {
	return bobotSeverity(severity)
}

// fullPath menggabungkan path + query string seperti WAFRequest.full_path.
func (r *Request) fullPath() string {
	p := r.Path
	if p == "" {
		p = "/"
	}
	if r.Query != "" {
		return p + "?" + r.Query
	}
	return p
}

// potong memangkas string ke n rune (setara slicing str Python per code point).
func potong(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// zona adalah satu area teks yang dipindai.
type zona struct {
	nama string // path | header | body
	teks string
}

// zones membangun 3 zona pemindaian: path (full path), header (semua header
// digabung "k=v", karena Log4Shell dkk. sering lewat header acak), dan body
// (decode latin-1 seperti Python).
func (e *Engine) zones(r *Request) []zona {
	pathZone := potong(r.fullPath(), scanLimit)

	// Header: nama di-lowercase seperti WAFRequest.create Python; urutan
	// di-sort agar deterministik (Python memakai urutan insert dict).
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 40 {
		keys = keys[:40]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, strings.ToLower(k)+"="+potong(r.Headers[k], 800))
	}
	headerZone := potong(strings.Join(parts, " "), scanLimit)

	var bodyZone string
	b := r.Body
	if len(b) > scanLimit {
		b = b[:scanLimit]
	}
	if len(b) > 0 {
		bodyZone = latin1ToString(b)
	}

	return []zona{
		{nama: "path", teks: pathZone},
		{nama: "header", teks: headerZone},
		{nama: "body", teks: bodyZone},
	}
}

// latin1ToString men-decode byte menjadi string ala Python bytes.decode("latin-1")
// (setiap byte -> code point yang sama).
func latin1ToString(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// unquote men-decode %XX seperti urllib.parse.unquote Python:
// '+' TIDAK diubah menjadi spasi, sekuens % yang tidak valid dibiarkan apa adanya.
func unquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			b.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 3
		} else {
			b.WriteByte(c)
			i++
		}
	}
	// Python: byte hasil decode di-decode lagi sebagai UTF-8 (errors=replace).
	return strings.ToValidUTF8(b.String(), "\uFFFD")
}

// multiUnquote melakukan URL-decode berulang (maks 3x, berhenti bila stabil)
// agar payload ter-encode tetap terdeteksi signature.
func multiUnquote(s string) string {
	prev := ""
	cur := s
	for i := 0; i < 3; i++ {
		if cur == prev {
			break
		}
		prev = cur
		cur = unquote(cur)
	}
	return cur
}

// evidenceSnippet memotong 24 char di kiri-kanan kecocokan, mengganti newline
// dengan spasi, dan memangkas ke 160 char — sama seperti Python.
func evidenceSnippet(candidate string, byteStart, byteEnd int) string {
	// Indeks Go adalah byte; Python memakai code point -> konversi dulu.
	startRune := utf8.RuneCountInString(candidate[:byteStart])
	endRune := startRune + utf8.RuneCountInString(candidate[byteStart:byteEnd])
	rs := []rune(candidate)
	s := startRune - 24
	if s < 0 {
		s = 0
	}
	e := endRune + 24
	if e > len(rs) {
		e = len(rs)
	}
	ev := strings.ReplaceAll(string(rs[s:e]), "\n", " ")
	return potong(ev, 160)
}

// pindaiRule memindai satu rule di semua zona; mengembalikan satu hit pertama
// (satu hit per rule, menghindari skor ganda).
func (e *Engine) pindaiRule(rule Rule, zones []zona) (Hit, bool) {
	for _, z := range zones {
		if z.teks == "" {
			continue
		}
		// Pindai versi mentah DAN versi ter-decode (lawan obfuskasi).
		decoded := multiUnquote(z.teks)
		candidates := []string{z.teks}
		if decoded != z.teks {
			candidates = append(candidates, decoded)
		}
		for _, cand := range candidates {
			for _, re := range rule.Patterns {
				if loc := re.FindStringIndex(cand); loc != nil {
					return Hit{
						RuleID:   rule.ID,
						Name:     rule.Name,
						Category: rule.Category,
						Severity: rule.Severity,
						Evidence: evidenceSnippet(cand, loc[0], loc[1]),
						Location: z.nama,
						Weight:   rule.Weight,
					}, true
				}
			}
		}
	}
	return Hit{}, false
}

// Triage memindai request dan menentukan aksi: allow | agent | block.
// Skor = jumlah bobot hit + anomali struktural, dibatasi maks 100.
func (e *Engine) Triage(r *Request) TriageResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	zones := e.zones(r)
	var hits []Hit
	for _, rule := range e.rules {
		if h, ok := e.pindaiRule(rule, zones); ok {
			hits = append(hits, h)
		}
	}

	score := 0.0
	for _, h := range hits {
		score += h.Weight
	}

	// Anomali struktural (bobot kecil, tapi menaikkan ke zona agent).
	var reasons []string
	if utf8.RuneCountInString(r.Query) > 2000 {
		score += 10
		reasons = append(reasons, "query string sangat panjang (>2000 char)")
	}
	if strings.Count(r.Query, "&") > 50 {
		score += 10
		reasons = append(reasons, "jumlah parameter tidak wajar (>50)")
	}
	// Python meng-uppercase method saat request dibuat; samakan di sini.
	if method := strings.ToUpper(r.Method); !isCommonMethod(method) {
		score += 10
		reasons = append(reasons, "HTTP method tidak umum: "+r.Method)
	}

	if score > 100 {
		score = 100
	}

	agentScore, blockScore := 25.0, 60.0
	if e.cfg != nil {
		agentScore = e.cfg.Thresholds.AgentScore
		blockScore = e.cfg.Thresholds.BlockScore
	}
	var action string
	switch {
	case score >= blockScore:
		action = "block"
	case score >= agentScore:
		action = "agent"
	default:
		action = "allow"
	}
	return TriageResult{Score: score, Action: action, Hits: hits, Reasons: reasons}
}

func isCommonMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}
