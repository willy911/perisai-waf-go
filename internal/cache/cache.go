// Package cache menyimpan respons upstream yang aman di-cache,
// lalu menyajikannya langsung tanpa meneruskan ke origin.
// Merupakan port dari perisai/cache.py (Python): cache respons
// WAF-side per site, TTL + batas entri (evict tertua dulu),
// batas ukuran objek, dan bypass lewat cookie sesi.
package cache

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
)

// DefaultBypassCookies adalah nama cookie (substring, case-insensitive)
// yang menandakan sesi personal — sama seperti DEFAULT_BYPASS_COOKIES
// di Python. Dipakai bila site.CacheBypassCookies kosong.
var DefaultBypassCookies = []string{
	"session", "sess", "phpsessid", "wordpress_logged_in",
	"token", "auth", "sid", "userid", "user_id",
}

// Batasan default saat field site bernilai nol (guard "or 2048"/"or 60"/
// "or 1000" di Python).
const (
	defaultTTLSeconds  = 60
	defaultMaxEntries  = 1000
	defaultMaxObjectKB = 2048
)

// Entry adalah satu respons yang disimpan di cache.
type Entry struct {
	Body        []byte
	Header      http.Header
	ContentType string
	Expiry      time.Time
	Status      int

	inserted time.Time
}

// Cache adalah cache dalam memori per site, aman untuk
// multi-goroutine.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*Entry
	hits    int64
	misses  int64
}

// New membuat Cache baru.
func New() *Cache {
	return &Cache{entries: make(map[string]*Entry)}
}

// cacheKey menggabungkan siteID dan key pemanggil menjadi key
// internal. Pemisah \x00 tidak mungkin muncul di keduanya.
func cacheKey(siteID, key string) string {
	return siteID + "\x00" + key
}

// MakeKey membangun key cache standar: siteID|METHOD|host|path|query,
// seperti PageCache.make_key di Python.
func MakeKey(siteID, method, host, path, query string) string {
	return siteID + "|" + strings.ToUpper(method) + "|" +
		strings.ToLower(host) + "|" + path + "|" + query
}

// Get mengembalikan entry bila masih ada dan belum kedaluwarsa.
func (c *Cache) Get(siteID, key string) (Entry, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[cacheKey(siteID, key)]
	if !ok {
		c.misses++
		return Entry{}, false
	}
	if !e.Expiry.After(now) {
		delete(c.entries, cacheKey(siteID, key))
		c.misses++
		return Entry{}, false
	}
	c.hits++
	return *e, true
}

// Put menyimpan entry dengan TTL detik. Entry yang body-nya melebihi
// batas ukuran objek tidak disimpan (diam-diam, sesuai perilaku
// Python yang me-return False). Entri yang sudah kedaluwarsa dibuang
// dulu, lalu bila jumlah entri mencapai batas, yang tertua di-evict.
func (c *Cache) Put(siteID, key string, e Entry, ttlSeconds int) {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTLSeconds
	}
	now := time.Now()
	e.Expiry = now.Add(time.Duration(ttlSeconds) * time.Second)
	e.inserted = now

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(e.Body) > defaultMaxObjectKB*1024 {
		return
	}
	for k, old := range c.entries {
		if !old.Expiry.After(now) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= defaultMaxEntries && len(c.entries) > 0 {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, old := range c.entries {
			if first || old.inserted.Before(oldest) {
				oldestKey, oldest, first = k, old.inserted, false
			}
		}
		delete(c.entries, oldestKey)
	}
	cp := e
	c.entries[cacheKey(siteID, key)] = &cp
}

// PutForSite menyimpan entry dengan aturan per site: abaikan bila
// cache dimatikan, body melebihi site.CacheMaxObjectKB, atau TTL
// hasil min(site.CacheTTL, max-age header) tidak positif.
// Mengembalikan true bila entry tersimpan.
// Ini padanan dekat PageCache.store di Python.
func (c *Cache) PutForSite(site *config.Site, key string, e Entry) bool {
	if site == nil || !site.CacheEnabled {
		return false
	}
	maxKB := site.CacheMaxObjectKB
	if maxKB <= 0 {
		maxKB = defaultMaxObjectKB
	}
	if len(e.Body) > maxKB*1024 {
		return false
	}
	if hasSetCookieOrNoStore(e.Header) {
		return false
	}
	ttl := site.CacheTTL
	if ttl <= 0 {
		ttl = defaultTTLSeconds
	}
	if ma, ok := maxAge(e.Header); ok && ma < float64(ttl) {
		ttl = int(ma)
	}
	if ttl <= 0 {
		return false
	}
	now := time.Now()
	e.Expiry = now.Add(time.Duration(ttl) * time.Second)
	e.inserted = now

	maxEntries := site.CacheMaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, old := range c.entries {
		if !old.Expiry.After(now) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= maxEntries && len(c.entries) > 0 {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, old := range c.entries {
			if first || old.inserted.Before(oldest) {
				oldestKey, oldest, first = k, old.inserted, false
			}
		}
		delete(c.entries, oldestKey)
	}
	cp := e
	c.entries[cacheKey(site.ID, key)] = &cp
	return true
}

// BypassedByCookies mengembalikan true bila header Cookie mengandung
// cookie sesi (daftar per site, atau default bila kosong) —
// request seperti itu tidak boleh dilayani dari cache.
func (c *Cache) BypassedByCookies(site *config.Site, cookieHeader string) bool {
	if cookieHeader == "" {
		return false
	}
	needles := DefaultBypassCookies
	if site != nil && len(site.CacheBypassCookies) > 0 {
		needles = site.CacheBypassCookies
	}
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		name, _, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		for _, n := range needles {
			if strings.Contains(name, strings.ToLower(n)) {
				return true
			}
		}
	}
	return false
}

// Purge menghapus entri cache milik site. Bila url tidak kosong,
// hanya entri dengan path+query cocok yang dihapus.
// Mengembalikan jumlah entri yang terhapus.
func (c *Cache) Purge(siteID, url string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k := range c.entries {
		site, rest, found := strings.Cut(k, "\x00")
		if !found || site != siteID {
			continue
		}
		if url != "" {
			// rest berbentuk siteID|METHOD|host|path|query (dari MakeKey)
			parts := strings.SplitN(rest, "|", 5)
			if len(parts) != 5 {
				continue
			}
			full := parts[3]
			if parts[4] != "" {
				full += "?" + parts[4]
			}
			if full != url && parts[3] != url {
				continue
			}
		}
		delete(c.entries, k)
		n++
	}
	return n
}

// Stats mengembalikan statistik cache (opsional per site).
type Stats struct {
	Hits     int64
	Misses   int64
	HitRatio float64
	Entries  int
	Bytes    int64
}

func (c *Cache) Stats(siteID string) Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Stats{Hits: c.hits, Misses: c.misses}
	denom := s.Hits + s.Misses
	if denom > 0 {
		s.HitRatio = float64(s.Hits) / float64(denom)
	}
	for k, e := range c.entries {
		if siteID != "" {
			site, _, found := strings.Cut(k, "\x00")
			if !found || site != siteID {
				continue
			}
		}
		s.Entries++
		s.Bytes += int64(len(e.Body))
	}
	return s
}

// maxAge mengekstrak direktif max-age dari header Cache-Control.
func maxAge(h http.Header) (float64, bool) {
	cc := h.Get("Cache-Control")
	if cc == "" {
		return 0, false
	}
	for _, d := range strings.Split(cc, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		v, ok := strings.CutPrefix(d, "max-age=")
		if !ok {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		if secs < 0 {
			secs = 0
		}
		return float64(secs), true
	}
	return 0, false
}

// hasSetCookieOrNoStore padanan _no_store di Python: respons yang
// membawa Set-Cookie atau Cache-Control private/no-store/no-cache
// tidak boleh disimpan.
func hasSetCookieOrNoStore(h http.Header) bool {
	if h.Get("Set-Cookie") != "" {
		return true
	}
	cc := strings.ToLower(h.Get("Cache-Control"))
	return strings.Contains(cc, "no-store") ||
		strings.Contains(cc, "private") ||
		strings.Contains(cc, "no-cache")
}
