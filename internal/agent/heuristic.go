// Package agent berisi AI agent Perisai WAF untuk triase trafik abu-abu.
// Port dari perisai/agent/ (heuristic.py, llm.py, systemone.py, orchestrator.py).
//
// Arsitektur: rules engine memindai tiap request; skor 25-59 (zona abu-abu)
// diteruskan ke Orchestrator yang memilih backend (systemone -> llm ->
// heuristic), menegakkan batas kebijakan, dan mencatat hasilnya ke storage.
package agent

import (
	"errors"
	"html"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/willy911/perisai-waf/internal/rules"
)

// keywordSerangan: keyword serangan per kategori, dalam urutan Python asli
// (urutan penting: keyword pertama yang cocok menentukan top_keyword).
var keywordSerangan = []struct {
	kategori string
	kata     []string
}{
	{"sqli", []string{"union select", "information_schema", "load_file", "into outfile",
		"xp_cmdshell", "or 1=1", "' or '", "\" or \"", "sleep(", "benchmark(",
		"extractvalue(", "updatexml(", "pg_sleep("}},
	{"xss", []string{"<script", "javascript:", "onload=", "onerror=", "onclick=",
		"<iframe", "<svg", "document.cookie", "document.write", "eval(",
		"alert(", "prompt(", "confirm(", "<img", "expression("}},
	{"rce", []string{";cat ", ";ls ", "|cat ", "&&", "$(", "`", "system(", "popen(",
		"shell_exec(", "passthru(", "proc_open(", "runtime.getruntime",
		"processbuilder", "__import__", "os.system"}},
	{"lfi", []string{"../", "..\\", "/etc/passwd", "/etc/shadow", "php://", "file://",
		"expect://", "data://", "boot.ini"}},
	{"cve", []string{"${jndi:", "${${", "class.module.classloader", "_method=__construct",
		"%{#context", "autodiscover.json"}},
	{"ssrf", []string{"169.254.169.254", "metadata.google"}},
	{"scanner", []string{"sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
		"ffuf", "nuclei", "hydra", "metasploit", "acunetix", "wpscan"}},
}

var (
	b64Re        = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	mixedCaseRe  = regexp.MustCompile(`<[Ss][Cc][Rr][Ii][Pp][Tt]`)
	highEntroRe  = regexp.MustCompile(`[A-Za-z0-9+/=%]{64,}`)
	errBadEscape = errors.New("escape sequence unicode tidak valid")
)

// shannon menghitung entropi Shannon sebuah string (basis 2).
func shannon(s string) float64 {
	if s == "" {
		return 0.0
	}
	freq := map[rune]int{}
	var n float64
	for _, ch := range s {
		freq[ch]++
		n++
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// unquotePython meniru urllib.parse.unquote: %XX valid di-decode, sekuens %
// tidak valid dibiarkan apa adanya, '+' TIDAK diubah jadi spasi, hasil byte
// di-decode sebagai UTF-8 dengan errors=replace.
func unquotePython(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 3
		} else {
			b.WriteByte(c)
			i++
		}
	}
	return strings.ToValidUTF8(b.String(), "\uFFFD")
}

func isHex(c byte) bool {
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

func parseHexN(b []byte) (int, bool) {
	v := 0
	for _, c := range b {
		if !isHex(c) {
			return 0, false
		}
		v = v*16 + int(hexVal(c))
	}
	return v, true
}

// decodeUnicodeEscapes meniru Python: text.encode("utf-8").decode("unicode_escape").
// Berjalan di level byte: byte non-escape (termasuk non-ASCII) lolos apa adanya
// sebagai code point latin-1 — persis seperti codec unicode_escape Python yang
// memetakan byte 0x80-0xFF ke U+0080-U+00FF. Escape tak dikenal dipertahankan
// apa adanya; escape rusak (terpotong/\x invalid) mengembalikan error sehingga
// pemanggil melewatkan langkah ini, sama seperti try/except Python.
//
// Penyimpangan dari Python: \N{nama} selalu dianggap error (Python bisa
// me-resolve nama unicode yang valid); praktisnya jarang dipakai penyerang.
func decodeUnicodeEscapes(s string) (string, error) {
	b := []byte(s)
	out := make([]rune, 0, len(b))
	i := 0
	for i < len(b) {
		c := b[i]
		if c != '\\' {
			out = append(out, rune(c))
			i++
			continue
		}
		i++
		if i >= len(b) {
			return "", errBadEscape // backslash di ujung string
		}
		e := b[i]
		i++
		switch e {
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'v':
			out = append(out, '\v')
		case 'a':
			out = append(out, '\a')
		case '\\':
			out = append(out, '\\')
		case '\'':
			out = append(out, '\'')
		case '"':
			out = append(out, '"')
		case 'x', 'u', 'U':
			need := 2
			if e == 'u' {
				need = 4
			} else if e == 'U' {
				need = 8
			}
			if i+need > len(b) {
				return "", errBadEscape
			}
			v, ok := parseHexN(b[i : i+need])
			if !ok {
				return "", errBadEscape
			}
			r := rune(v)
			if r >= 0xD800 && r <= 0xDFFF {
				r = '\uFFFD' // surrogate tunggal tak valid di Go string
			}
			out = append(out, r)
			i += need
		case 'N':
			return "", errBadEscape // \N{nama}: lihat catatan di atas
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(b) && j-i < 2 && b[j] >= '0' && b[j] <= '7' {
				j++
			}
			v := 0
			for _, d := range b[i-1 : j] {
				v = v*8 + int(d-'0')
			}
			out = append(out, rune(v))
			i = j
		default:
			// escape tak dikenal: Python mempertahankannya apa adanya
			out = append(out, '\\', rune(e))
		}
	}
	return string(out), nil
}

// multiDecode melakukan decode berlapis (URL-decode, HTML entities, unicode
// escape) untuk membongkar obfuskasi, serta mendeteksi teknik evasion.
// Mengembalikan (teks_final, daftar_flag_evasion_terurut).
func multiDecode(raw string) (string, []string) {
	flagSet := map[string]bool{}
	add := func(f string) { flagSet[f] = true }

	text := raw
	if strings.Contains(text, "%00") || strings.Contains(text, "\x00") {
		add("null_byte")
	}
	if n := len(text); n > 0 && float64(strings.Count(text, "%"))/float64(n) > 0.3 {
		add("excessive_percent_encoding")
	}

	deep := true
	for k := 0; k < 4; k++ {
		prev := text
		text = unquotePython(text)
		text = html.UnescapeString(text)
		if dec, err := decodeUnicodeEscapes(text); err == nil {
			text = dec
		}
		if text == prev {
			deep = false
			break
		}
	}
	if deep {
		add("deep_nesting_decode")
	}
	if text != raw && unquotePython(raw) != raw {
		once := unquotePython(raw)
		if unquotePython(once) != once {
			add("double_encoding")
		}
	}

	// Kandidat base64: decode bila hasilnya printable (dedup, urutan kemunculan
	// pertama; Python memakai set() yang urutannya acak — lihat penyimpangan).
	seen := map[string]bool{}
	for _, cand := range b64Re.FindAllString(text, -1) {
		if seen[cand] {
			continue
		}
		seen[cand] = true
		dec, err := decodeBase64Strict(cand)
		if err != nil {
			continue
		}
		printable := 0
		for _, ch := range dec {
			if (ch >= 32 && ch < 127) || ch == '\n' || ch == '\r' || ch == '\t' {
				printable++
			}
		}
		n := len([]rune(dec))
		if n == 0 {
			n = 1
		}
		if dec != "" && float64(printable)/float64(n) > 0.85 && len([]rune(dec)) >= 8 {
			text += " " + dec
			add("embedded_base64")
			break
		}
	}

	flags := make([]string, 0, len(flagSet))
	for f := range flagSet {
		flags = append(flags, f)
	}
	sort.Strings(flags)
	return text, flags
}

// decodeBase64Strict meniru base64.b64decode(cand, validate=True): alfabet
// ketat dan panjang harus kelipatan 4.
func decodeBase64Strict(cand string) (string, error) {
	if len(cand)%4 != 0 {
		return "", errBadEscape
	}
	for i := 0; i < len(cand); i++ {
		c := cand[i]
		if c == '=' {
			// padding hanya boleh di akhir, maks 2
			if i < len(cand)-2 {
				return "", errBadEscape
			}
			continue
		}
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' || c == '+' || c == '/') {
			return "", errBadEscape
		}
	}
	out := make([]byte, 0, len(cand)*3/4)
	for i := 0; i < len(cand); i += 4 {
		var v uint32
		pad := 0
		for j := 0; j < 4; j++ {
			c := cand[i+j]
			var d uint32
			switch {
			case c >= 'A' && c <= 'Z':
				d = uint32(c - 'A')
			case c >= 'a' && c <= 'z':
				d = uint32(c-'a') + 26
			case c >= '0' && c <= '9':
				d = uint32(c-'0') + 52
			case c == '+':
				d = 62
			case c == '/':
				d = 63
			default: // '='
				pad++
			}
			v = v<<6 | d
		}
		out = append(out, byte(v>>16), byte(v>>8), byte(v))
		out = out[:len(out)-pad]
	}
	// decode latin-1: tiap byte -> code point yang sama
	r := make([]rune, len(out))
	for i, c := range out {
		r[i] = rune(c)
	}
	return string(r), nil
}

// roundHalfEven meniru Python round(x, places): round-half-to-even
// (banker's rounding). Dipakai untuk confidence/latensi/durasi agar nilainya
// sama persis dengan Python (mis. round(0.625, 2) = 0.62, bukan 0.63).
// Hanya untuk x >= 0, yang mencakup semua pemakaian di package ini.
func roundHalfEven(x float64, places int) float64 {
	m := math.Pow(10, float64(places))
	scaled := x * m
	f := math.Floor(scaled)
	switch diff := scaled - f; {
	case diff < 0.5:
		return f / m
	case diff > 0.5:
		return (f + 1) / m
	default:
		if math.Mod(f, 2) == 0 {
			return f / m
		}
		return (f + 1) / m
	}
}

// headerGet mengambil header tanpa peduli kapitalisasi nama (Python me-lowercase
// semua nama header saat request dibuat).
func headerGet(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// potongRune memangkas string ke n rune (setara slicing str Python).
func potongRune(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// HeuristicBackend menganalisis trafik abu-abu tanpa LLM: decode berlapis,
// pindai keyword serangan, deteksi evasion, lalu skor + keputusan.
type HeuristicBackend struct{}

// NewHeuristicBackend membuat backend heuristic.
func NewHeuristicBackend() *HeuristicBackend { return &HeuristicBackend{} }

// Name mengembalikan nama backend untuk interface Backend.
func (b *HeuristicBackend) Name() string { return "heuristic" }

// Available selalu true: heuristic tidak butuh koneksi ke mana pun.
func (b *HeuristicBackend) Available() bool { return true }

// rawSurface membangun permukaan teks mentah dari request (full path + body
// 8KB latin-1 + user-agent + referer + cookie 1000 char), seperti Python.
func rawSurface(r *rules.Request) string {
	p := r.Path
	if p == "" {
		p = "/"
	}
	full := p
	if r.Query != "" {
		full = p + "?" + r.Query
	}
	body := r.Body
	if len(body) > 8192 {
		body = body[:8192]
	}
	br := make([]rune, len(body))
	for i, c := range body {
		br[i] = rune(c)
	}
	return full + "\n" + string(br) + "\n" +
		headerGet(r.Headers, "user-agent") + "\n" +
		headerGet(r.Headers, "referer") + "\n" +
		potongRune(headerGet(r.Headers, "cookie"), 1000)
}

// Analyze menjalankan analisis heuristic atas request + hasil triase engine.
func (b *HeuristicBackend) Analyze(r *rules.Request, t rules.TriageResult) (Verdict, error) {
	decoded, evasion := multiDecode(rawSurface(r))
	lowered := strings.ToLower(decoded)

	var indicators []string
	var reasoning []string
	var topKategori, topKeyword string

	for _, kw := range keywordSerangan {
		for _, kata := range kw.kata {
			if strings.Contains(lowered, kata) {
				indicators = append(indicators, kw.kategori+":"+kata)
				if topKeyword == "" {
					topKategori, topKeyword = kw.kategori, kata
				}
				break
			}
		}
	}
	for _, f := range evasion {
		indicators = append(indicators, "evasion:"+f)
	}

	// Mixed-case keyword = upaya evasion signature sederhana.
	if mixedCaseRe.MatchString(decoded) && strings.Contains(lowered, "<script") {
		dup := false
		for _, ind := range indicators {
			if strings.Contains(ind, "mixed_case") {
				dup = true
				break
			}
		}
		if !dup {
			indicators = append(indicators, "evasion:mixed_case_keyword")
		}
	}

	score := 10.0
	if len(indicators) > 0 {
		kats := map[string]bool{}
		nEvasion := 0
		for _, ind := range indicators {
			if strings.HasPrefix(ind, "evasion:") {
				nEvasion++
			} else {
				kats[strings.SplitN(ind, ":", 2)[0]] = true
			}
		}
		score += 25 * float64(len(kats))
		score += 8 * float64(nEvasion)
	}
	if len(t.Hits) > 0 {
		score += 10 // koroborasi dengan rules engine
		ids := map[string]bool{}
		for _, h := range t.Hits {
			ids[h.RuleID] = true
		}
		sorted := make([]string, 0, len(ids))
		for id := range ids {
			sorted = append(sorted, id)
		}
		sort.Strings(sorted)
		reasoning = append(reasoning,
			"Dikoroborasi "+strconv.Itoa(len(t.Hits))+" signature engine ("+
				strings.Join(sorted, ", ")+").")
	}
	for _, rs := range t.Reasons {
		reasoning = append(reasoning, "Anomali struktural: "+rs+".")
	}
	if len(evasion) > 0 {
		reasoning = append(reasoning,
			"Teknik evasion terdeteksi: "+strings.Join(evasion, ", ")+".")
	}
	if topKeyword != "" {
		reasoning = append(reasoning,
			"Keyword serangan '"+topKeyword+"' ditemukan setelah decode "+
				"berlapis (kategori "+topKategori+").")
	}

	// Entropi tinggi pada segmen panjang -> kemungkinan payload obfuscated.
	for _, seg := range highEntroRe.FindAllString(rawSurface(r), -1) {
		if shannon(seg) > 5.2 {
			indicators = append(indicators, "evasion:high_entropy_segment")
			score += 8
			reasoning = append(reasoning,
				"Segmen ber-entropi tinggi terdeteksi (obfuskasi).")
			break
		}
	}

	// Temuan kritis dari engine -> ambang block lebih rendah (tegas, bukan ragu).
	hasCritical := false
	for _, h := range t.Hits {
		if h.Severity == "critical" {
			hasCritical = true
			break
		}
	}
	blockAt := 55.0
	if hasCritical {
		blockAt = 45
	}
	var decision string
	switch {
	case score >= blockAt:
		decision = "block"
	case score >= 30:
		decision = "challenge"
	default:
		decision = "allow"
		if len(indicators) == 0 {
			reasoning = append(reasoning,
				"Tidak ada indikator serangan setelah analisis mendalam.")
		}
	}

	boundary := 0.0
	switch decision {
	case "block":
		boundary = blockAt
	case "challenge":
		boundary = 30
	}
	marginFrom := boundary
	if decision == "allow" {
		marginFrom = 30
	}
	margin := math.Abs(score - marginFrom)
	confidence := roundHalfEven(math.Min(0.95, 0.5+margin/120), 2)

	var suggested map[string]any
	if decision == "block" && topKeyword != "" && len([]rune(topKeyword)) >= 4 {
		suggested = map[string]any{
			"id":       "AI-" + strings.ToUpper(topKategori) + "-AUTO",
			"name":     "AI-learned: " + topKeyword,
			"category": topKategori,
			"severity": "high",
			"pattern":  regexp.QuoteMeta(topKeyword),
		}
		reasoning = append(reasoning,
			"Mengusulkan signature baru dari keyword dominan.")
	}

	return Verdict{
		Decision:      decision,
		Confidence:    confidence,
		Reasoning:     reasoning,
		Indicators:    indicators,
		SuggestedRule: suggested,
		Backend:       "heuristic",
	}, nil
}
