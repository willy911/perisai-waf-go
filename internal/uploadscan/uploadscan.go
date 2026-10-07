// Package uploadscan melindungi endpoint upload dari file berbahaya.
// Merupakan port dari perisai/uploadscan.py (Python): pemeriksaan
// nama file (null byte, ekstensi diblokir, double-extension), magic
// bytes executable/PHP tersamar, dan signature konten (EICAR +
// pola webshell PHP umum).
package uploadscan

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/willy911/perisai-waf/internal/config"
)

// EICAR adalah string uji standar antivirus (bukan malware beneran).
var EICAR = []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" +
	"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

// DefaultBlockedExtensions dipakai bila config tidak menyebutkan
// daftar ekstensi — sama dengan default di perisai/config.py.
var DefaultBlockedExtensions = []string{
	"php", "phtml", "phar", "asp", "aspx", "jsp", "exe", "dll",
	"sh", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs",
}

// contentPattern adalah satu pola webshell beserta deskripsinya.
type contentPattern struct {
	re   *regexp.Regexp
	desc string
}

// Pola webshell / kode berbahaya dalam konten file — port langsung
// dari CONTENT_PATTERNS di Python.
var contentPatterns = []contentPattern{
	{regexp.MustCompile(`(?i)eval\s*\(\s*base64_decode\s*\(`), "eval(base64_decode)"},
	{regexp.MustCompile(`(?i)\b(shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(`), "fungsi eksekusi shell"},
	{regexp.MustCompile(`(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(`), "webshell via $_GET/$_POST"},
	{regexp.MustCompile(`(?is)preg_replace\s*\([^)]*/e['"]`), "preg_replace modifier /e"},
	{regexp.MustCompile(`(?i)\bcreate_function\s*\(`), "create_function"},
	{regexp.MustCompile(`(?i)\bassert\s*\(\s*\$`), "assert($...)"},
	{regexp.MustCompile(`(?is)<\?(php|=).*?\b(eval|system|exec|passthru)\s*\(`), "tag PHP + fungsi eksekusi"},
}

// magicExec adalah magic bytes executable beserta deskripsinya.
var magicExec = []struct {
	magic []byte
	desc  string
}{
	{[]byte("MZ"), "Windows executable (MZ)"},
	{[]byte{0x7f, 'E', 'L', 'F'}, "Linux executable (ELF)"},
}

// phpExts adalah ekstensi yang memang boleh berisi kode PHP.
var phpExts = map[string]bool{"php": true, "phtml": true, "phar": true}

// sampleLimit membatasi sampel konten yang dipindai (2 MB),
// sama seperti Python: data[:2*1024*1024].
const sampleLimit = 2 * 1024 * 1024

// Scan memindai satu file upload. Mengembalikan blocked=true beserta
// alasan bila file harus ditolak. Asumsi pemanggil sudah mengecek
// cfg.Enabled (mirip UploadScanner.scan di Python yang dipanggil
// setelah should_scan).
func Scan(filename string, content []byte, cfg config.UploadScanConfig) (blocked bool, reason string) {
	// 1. nama file
	if strings.ContainsRune(filename, 0) {
		return true, "null byte pada nama file"
	}
	lower := strings.ToLower(filename)
	blockedExts := blockedExtSet(cfg)
	parts := strings.Split(lower, ".")
	// double extension: shell.php.jpg atau foto.jpg.php — ekstensi
	// terlarang di antara nama dasar dan ekstensi akhir menandakan
	// penyamaran. (Python hanya memeriksa 3 bagian terakhir via
	// rsplit(".", 2); versi Go ini lebih ketat.)
	for _, p := range parts[1:max(1, len(parts)-1)] {
		if blockedExts[p] {
			return true, "double extension tersembunyi (." + p + ")"
		}
	}
	ext := ""
	if len(parts) >= 2 {
		ext = parts[len(parts)-1]
	}
	if blockedExts[ext] {
		return true, "ekstensi diblokir (." + ext + ")"
	}

	if len(content) == 0 {
		return false, ""
	}

	// 2. magic bytes
	for _, m := range magicExec {
		if bytes.HasPrefix(content, m.magic) {
			return true, "file executable terdeteksi (" + m.desc + ")"
		}
	}
	head := bytes.TrimLeft(content[:min(len(content), 200)], " \t\n\r")
	if bytes.HasPrefix(head, []byte("<?php")) || bytes.HasPrefix(head, []byte("<?=")) {
		if !phpExts[ext] {
			return true, "kode PHP disamarkan sebagai file lain"
		}
	}

	// 3. signature konten (cukup awal file; webshell biasanya kecil)
	sample := content
	if len(sample) > sampleLimit {
		sample = sample[:sampleLimit]
	}
	if bytes.Contains(sample, EICAR) {
		return true, "EICAR test signature terdeteksi"
	}
	for _, p := range contentPatterns {
		if p.re.Match(sample) {
			return true, "pola webshell: " + p.desc
		}
	}
	return false, ""
}

// blockedExtSet membangun himpunan ekstensi terblokir dari config
// (case-insensitive, tanpa titik depan). Daftar kosong jatuh kembali
// ke DefaultBlockedExtensions.
func blockedExtSet(cfg config.UploadScanConfig) map[string]bool {
	exts := cfg.BlockedExtensions
	if len(exts) == 0 {
		exts = DefaultBlockedExtensions
	}
	set := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = strings.TrimPrefix(strings.ToLower(e), ".")
		if e != "" {
			set[e] = true
		}
	}
	return set
}
