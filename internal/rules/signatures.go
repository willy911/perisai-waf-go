package rules

// Signature pack bawaan Perisai WAF — port persis dari perisai/rules/signatures.py.
//
// Setiap Rule punya severity -> bobot:
//   critical = 40, high = 25, medium = 15, low = 8
//
// Triase default: skor >= 25 -> AI agent, skor >= 60 -> block langsung.

import (
	"fmt"
	"regexp"
)

// Rule adalah satu signature deteksi. Pola dikompilasi dengan flag
// case-insensitive + dotall, setara Python re.compile(p, IGNORECASE|DOTALL).
type Rule struct {
	ID       string
	Name     string
	Category string // sqli|xss|rce|lfi|ssrf|cve|scanner|anomaly
	Severity string // critical|high|medium|low
	Patterns []*regexp.Regexp
	Weight   float64
}

// bobotSeverity memetakan severity -> bobot skor.
func bobotSeverity(severity string) float64 {
	switch severity {
	case "critical":
		return 40
	case "high":
		return 25
	case "medium":
		return 15
	case "low":
		return 8
	default:
		return 0
	}
}

// compilePattern mengkompilasi satu pola dengan flag (?is).
// RE2 (Go) mendukung \b seperti Python, tetapi TIDAK mendukung backreference
// (\1, \2, ...) — pola yang memakainya harus ditulis ulang sebagai alternasi.
func compilePattern(p string) (*regexp.Regexp, error) {
	return regexp.Compile("(?is)" + p)
}

// NewRule membangun Rule dari pola-pola string. Dipakai untuk custom rule
// dari learner/storage; mengembalikan error bila ada pola yang tidak valid.
func NewRule(id, name, category, severity string, patterns ...string) (Rule, error) {
	rs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := compilePattern(p)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %s: pola tidak valid %q: %w", id, p, err)
		}
		rs = append(rs, re)
	}
	return Rule{
		ID: id, Name: name, Category: category, Severity: severity,
		Patterns: rs, Weight: bobotSeverity(severity),
	}, nil
}

// mustRule seperti NewRule tetapi panic bila pola tidak valid.
// Hanya untuk signature bawaan yang polanya statis dan sudah terverifikasi.
func mustRule(id, name, category, severity string, patterns ...string) Rule {
	r, err := NewRule(id, name, category, severity, patterns...)
	if err != nil {
		panic(err)
	}
	return r
}

// builtinRules adalah seluruh 33 signature bawaan, port PERSIS dari Python
// (ID, nama, kategori, severity, dan pola regex sama).
//
// SATU PENYIMPANGAN: pola pertama SQLI-002 memakai backreference (\2) yang
// tidak didukung RE2/Go, sehingga ditulis ulang sebagai 6 alternasi eksplisit
// (kombinasi quote pembuka × quote opsional) yang ekuivalen secara perilaku.
var builtinRules = []Rule{
	// ---------------- SQL Injection ----------------
	mustRule("SQLI-001", "Union-based SQLi", "sqli", "high",
		`union\s+(all\s+|distinct\s+)?select`),
	mustRule("SQLI-002", "Boolean-based SQLi", "sqli", "high",
		// Python asli: (['"])\s*or\s+(['"]?)\d+\2\s*=\s*\2?\d+
		// Ditulis ulang tanpa backreference (RE2 tidak mendukung \2).
		`(?:'\s*or\s+\d+\s*=\s*\d+|"\s*or\s+\d+\s*=\s*\d+|'\s*or\s+'\d+'\s*=\s*'?\d+|"\s*or\s+"\d+"\s*=\s*"?\d+|'\s*or\s+"\d+"\s*=\s*"?\d+|"\s*or\s+'\d+'\s*=\s*'?\d+)`,
		`\bor\s+1\s*=\s*1\b`, `\band\s+1\s*=\s*1\b`),
	mustRule("SQLI-003", "Time-based SQLi", "sqli", "high",
		`\b(sleep|benchmark)\s*\(`, `pg_sleep\s*\(`,
		`waitfor\s+delay\s+['"]`),
	mustRule("SQLI-004", "Error-based SQLi", "sqli", "high",
		`\b(extractvalue|updatexml|floor\s*\(\s*rand)\s*\(`),
	mustRule("SQLI-005", "File operation SQLi", "sqli", "critical",
		`\bload_file\s*\(`, `\binto\s+(outfile|dumpfile)\b`),
	mustRule("SQLI-006", "Stacked query", "sqli", "critical",
		`;\s*(drop|alter|create|truncate)\s+(table|database)\b`,
		`xp_cmdshell`, `\bexec\s*\(\s*['"]`),
	mustRule("SQLI-007", "Schema enumeration", "sqli", "medium",
		`information_schema`, `\btable_name\b.*\bcolumn_name\b`),

	// ---------------- XSS ----------------
	mustRule("XSS-001", "Script tag", "xss", "critical",
		`<\s*script\b`),
	mustRule("XSS-002", "Javascript URI", "xss", "high",
		`javascript\s*:`, `\bvbscript\s*:`),
	mustRule("XSS-003", "Event handler", "xss", "high",
		`<[^>]*\bon(load|error|click|mouseover|mouseout|focus|blur|submit|change|keydown|keyup|dblclick)\s*=`),
	mustRule("XSS-004", "Dangerous tags", "xss", "high",
		`<\s*(iframe|object|embed|svg|math|form)\b`),
	mustRule("XSS-005", "DOM access", "xss", "high",
		`document\.(cookie|location|write|domain)`, `window\.(location|name)`),
	mustRule("XSS-006", "JS eval / Function", "xss", "medium",
		`\beval\s*\(`, `\bFunction\s*\(`, `setTimeout\s*\(\s*['"]`),
	mustRule("XSS-007", "Alert/prompt probe", "xss", "medium",
		`\b(alert|prompt|confirm)\s*\(`),
	mustRule("XSS-008", "CSS expression", "xss", "high",
		`expression\s*\(`, `-moz-binding\s*:`),

	// ---------------- RCE / Command injection ----------------
	mustRule("RCE-001", "OS command chaining", "rce", "critical",
		`(;|\||&&|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|ncat|python3?|perl|php|ruby|node|powershell|cmd)\b`),
	// Pola ini mengandung backtick literal sehingga dipakai string "..." biasa.
	mustRule("RCE-002", "Backtick execution", "rce", "critical",
		"`[^`]*\\b(cat|id|whoami|uname|ls)\\b[^`]*`"),
	mustRule("RCE-003", "PHP code exec", "rce", "critical",
		`\b(system|popen|passthru|shell_exec|proc_open|pcntl_exec|assert)\s*\(`),
	mustRule("RCE-004", "Java deserialization/RCE", "rce", "critical",
		`Runtime\.getRuntime`, `ProcessBuilder`, `java\.lang\.Process`),
	mustRule("RCE-005", "Python code exec", "rce", "critical",
		`__import__\s*\(`, `\bos\.(system|popen)\s*\(`,
		`subprocess\.(Popen|call|run)\s*\(`),
	mustRule("RCE-006", "SSTI probe", "rce", "high",
		`\{\{.*\}\}`, `\$\{.*\}`, `<%.*%>`),

	// ---------------- LFI / RFI / Path traversal ----------------
	mustRule("LFI-001", "Path traversal", "lfi", "high",
		`\.\./`, `\.\.\\`, `%2e%2e`, `%252e`),
	mustRule("LFI-002", "Sensitive file access", "lfi", "critical",
		`/etc/(passwd|shadow|hosts|group)`, `boot\.ini`, `win\.ini`),
	mustRule("LFI-003", "PHP wrapper", "lfi", "critical",
		`\b(php|file|expect|data|zip|phar|glob)\s*://`),

	// ---------------- SSRF ----------------
	mustRule("SSRF-001", "Cloud metadata", "ssrf", "critical",
		`169\.254\.169\.254`, `metadata\.google\.internal`, `metadata\.google\b`),

	// ---------------- CVE signatures ----------------
	mustRule("CVE-001", "Log4Shell", "cve", "critical",
		`\$\{\s*jndi\s*:`, `\$\{\$\{`, `\$\{lower\s*:j\}`),
	mustRule("CVE-002", "Spring4Shell", "cve", "critical",
		`class\.module\.classLoader`, `classLoader\.(resources|URLs)`),
	mustRule("CVE-003", "ThinkPHP RCE", "cve", "high",
		`_method\s*=\s*__construct`, `filter\[\]\s*=\s*system`),
	mustRule("CVE-004", "ProxyShell/ProxyLogon", "cve", "high",
		`autodiscover\.json`, `/ecp/.*xxe|/oab/.*`),
	mustRule("CVE-005", "Struts OGNL", "cve", "critical",
		`%\{#context`, `ognl\.OgnlContext`),
	mustRule("CVE-006", "Recon: sensitive paths", "cve", "medium",
		`(^|/)\.git/config`, `(^|/)\.env\b`, `wp-config\.php\.bak`,
		`\.DS_Store`, `server-status`),
	mustRule("CVE-007", "Java webapp file access", "cve", "high",
		`/WEB-INF/`, `/META-INF/`,
		`/(server|context|web|struts)\.xml\b`),
	// CVE-008: teknik aktual CVE-2026-21589 (watchTowr, 2026-10-07).
	// atlassian-plugins-webresource.jar mengubah "::" menjadi "/" di routing,
	// sehingga traversal berbentuk "..::..::..::<dir>::file" lolos dari
	// pertahanan strip-slash dan TIDAK mengandung "/WEB-INF/" literal —
	// CVE-007 tidak menangkapnya. "::" ganda di path praktis tidak pernah
	// muncul di trafik normal (IPv6 pakai bracket di Host, bukan path).
	mustRule("CVE-008", "Atlassian :: traversal (CVE-2026-21589)", "cve", "high",
		`\.\.(::|%3a%3a)`, `(::|%3a%3a)\.\.`,
		`/(WEB-INF|META-INF)(::|%3a%3a)`),

	// ---------------- Scanner / bot jahat ----------------
	mustRule("SCAN-001", "Known scanner UA", "scanner", "high",
		`sqlmap|nikto|nmap|masscan|dirbuster|gobuster|ffuf|nuclei|hydra|metasploit|acunetix|nessus|openvas|wpscan|zgrab|shodan`),
}
