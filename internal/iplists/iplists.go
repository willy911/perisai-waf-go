// Package iplists menyediakan whitelist/blacklist IP manual (IP tunggal atau
// CIDR, scope global/per-site, dengan masa kedaluwarsa opsional) di atas
// penyimpanan SQLite.
//
// Merupakan port dari perisai/iplists.py (Python). Anggota grup IP diperlakukan
// seperti entri manual dengan scope "global".
package iplists

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/willy911/perisai-waf/internal/storage"
)

// entry adalah satu baris cache: hasil parse entri manual maupun anggota grup.
type entry struct {
	prefix    netip.Prefix // CIDR yang sudah dinormalisasi
	list      string       // "white" atau "black"
	scope     string       // "global" atau id site
	expiresAt float64      // epoch detik; 0 = tidak pernah kedaluwarsa
}

// IPLists memeriksa IP terhadap daftar putih/hitam dengan cache dalam-memori.
// Aman dipakai dari banyak goroutine (dikunci mutex sendiri).
type IPLists struct {
	store *storage.Storage
	mu    sync.RWMutex
	cache []entry // nil = belum dimuat / sudah di-invalidate
}

// New membuat IPLists di atas storage yang diberikan.
func New(store *storage.Storage) *IPLists {
	return &IPLists{store: store}
}

// Invalidate membuang cache dalam-memori sehingga pemuatan berikutnya membaca
// ulang dari database. Wajib dipanggil setelah dashboard mengubah daftar.
func (l *IPLists) Invalidate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cache = nil
}

// IsWhitelisted melaporkan true bila IP cocok dengan CIDR di entri "white"
// atau grup "white" (scope global; lihat check).
func (l *IPLists) IsWhitelisted(ip string) bool {
	return l.check(ip, "") == "white"
}

// IsBlacklisted melaporkan true bila IP cocok dengan CIDR di entri "black"
// atau grup "black" DAN tidak di-whitelist. Whitelist punya prioritas:
// IP yang di-whitelist selalu bypass, termasuk terhadap blacklist.
func (l *IPLists) IsBlacklisted(ip string) bool {
	return l.check(ip, "") == "black"
}

// Check adalah versi ekspor dari check: dipakai pipeline proxy yang butuh
// scope per-site. Mengembalikan "white", "black", atau "" (tidak cocok).
// Whitelist menang atas blacklist; entri kedaluwarsa dan scope tak cocok
// dilewati. IP yang tidak valid selalu menghasilkan "".
func (l *IPLists) Check(ip string, siteID string) string {
	return l.check(ip, siteID)
}

// check adalah padanan check() Python: kembalikan "white", "black", atau "".
// Whitelist menang atas blacklist; entri kedaluwarsa dan scope tak cocok
// dilewati. IP yang tidak valid selalu menghasilkan "".
func (l *IPLists) check(ip string, siteID string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	entries, err := l.load()
	if err != nil {
		return ""
	}
	now := float64(time.Now().UnixNano()) / 1e9
	foundBlack := false
	for _, e := range entries {
		if e.expiresAt > 0 && e.expiresAt < now {
			continue
		}
		if e.scope != "global" && e.scope != siteID {
			continue
		}
		if !e.prefix.Contains(addr) {
			continue
		}
		if e.list == "white" {
			return "white" // whitelist menang, langsung keluar
		}
		foundBlack = true
	}
	if foundBlack {
		return "black"
	}
	return ""
}

// load memuat (dan meng-cache) semua entri manual plus anggota grup.
// Entri rusak (CIDR tidak bisa di-parse) dilewati, seperti di Python.
func (l *IPLists) load() ([]entry, error) {
	l.mu.RLock()
	if l.cache != nil {
		c := l.cache
		l.mu.RUnlock()
		return c, nil
	}
	l.mu.RUnlock()

	var entries []entry

	// entri manual
	raw, err := l.store.ListIPEntries()
	if err != nil {
		return nil, err
	}
	for _, d := range raw {
		p, ok := parseCIDR(str(d["network"], ""))
		if !ok {
			continue // entri rusak -> lewati
		}
		entries = append(entries, entry{
			prefix:    p,
			list:      str(d["list"], ""),
			scope:     str(d["scope"], "global"),
			expiresAt: fnum(d["expires_at"]),
		})
	}

	// anggota grup IP diperlakukan seperti entri manual (scope global)
	groups, err := l.store.ListIPGroups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		kind := str(g["kind"], "")
		if kind != "white" && kind != "black" {
			continue
		}
		members, _ := g["members"].([]string)
		for _, cidr := range members {
			p, ok := parseCIDR(cidr)
			if !ok {
				continue
			}
			entries = append(entries, entry{
				prefix: p, list: kind, scope: "global",
			})
		}
	}

	if entries == nil {
		// slice kosong non-nil: menandai cache sudah dimuat (nil = belum)
		entries = []entry{}
	}
	l.mu.Lock()
	l.cache = entries
	l.mu.Unlock()
	return entries, nil
}

// parseCIDR memvalidasi dan menormalisasi CIDR seperti
// ipaddress.ip_network(c, strict=False): IP tunggal menjadi /32 (atau /128),
// dan bit host di-mask ("10.0.0.5/24" -> "10.0.0.0/24").
func parseCIDR(s string) (netip.Prefix, bool) {
	c := strings.TrimSpace(s)
	if c == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(c); err == nil {
		return p.Masked(), true
	}
	if addr, err := netip.ParseAddr(c); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// str mengambil string dari map storage (kolom TEXT), dengan nilai default
// bila tidak ada / nil.
func str(v any, def string) string {
	if v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

// fnum mengambil nilai numerik dari map storage (kolom REAL); nil -> 0.
func fnum(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	default:
		return 0
	}
}
