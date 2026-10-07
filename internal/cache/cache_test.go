package cache

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
)

func siteCache() *config.Site {
	return &config.Site{
		ID:               "s1",
		CacheEnabled:     true,
		CacheTTL:         60,
		CacheMaxEntries:  1000,
		CacheMaxObjectKB: 2048,
	}
}

func entry(body string) Entry {
	return Entry{
		Body:        []byte(body),
		Header:      http.Header{"Content-Type": []string{"text/html"}},
		ContentType: "text/html",
		Status:      200,
	}
}

func key(path string) string {
	return MakeKey("s1", "GET", "cache.test", path, "")
}

// Cache mati secara default: tidak menyimpan, tidak hit.
func TestDisabled(t *testing.T) {
	c := New()
	site := &config.Site{ID: "s1"} // CacheEnabled false
	if c.PutForSite(site, key("/"), entry("x")) {
		t.Fatal("PutForSite harusnya false saat cache dimatikan")
	}
	if _, ok := c.Get(site.ID, key("/")); ok {
		t.Fatal("Get harusnya miss")
	}
}

// Simpan lalu hit.
func TestHitSetelahSimpan(t *testing.T) {
	c := New()
	site := siteCache()
	if !c.PutForSite(site, key("/halo"), entry("<h1>hi</h1>")) {
		t.Fatal("PutForSite harusnya true")
	}
	e, ok := c.Get(site.ID, key("/halo"))
	if !ok {
		t.Fatal("Get harusnya HIT")
	}
	if string(e.Body) != "<h1>hi</h1>" {
		t.Fatalf("body salah: %q", e.Body)
	}
	if e.Status != 200 || e.ContentType != "text/html" {
		t.Fatalf("metadata salah: %+v", e)
	}
}

// Cookie sesi memicu bypass.
func TestBypassCookieSesi(t *testing.T) {
	c := New()
	site := siteCache()
	for _, ck := range []string{
		"PHPSESSID=abc123",
		"wordpress_logged_in_x=1",
		"sessionid=z",
		"auth_token=q",
	} {
		if !c.BypassedByCookies(site, ck) {
			t.Fatalf("cookie %q harusnya bypass", ck)
		}
	}
	if c.BypassedByCookies(site, "theme=dark; lang=id") {
		t.Fatal("cookie biasa jangan bypass")
	}
	if c.BypassedByCookies(site, "") {
		t.Fatal("cookie kosong jangan bypass")
	}
	// daftar custom per site
	site.CacheBypassCookies = []string{"mysess"}
	if c.BypassedByCookies(site, "PHPSESSID=abc") {
		t.Fatal("daftar custom harus menggantikan default")
	}
	if !c.BypassedByCookies(site, "mysess=1") {
		t.Fatal("mysess harus bypass")
	}
}

// Objek lebih besar dari max object KB tidak disimpan.
func TestObjekTerlaluBesar(t *testing.T) {
	c := New()
	site := siteCache()
	site.CacheMaxObjectKB = 1 // 1 KB
	e := entry("x")
	e.Body = make([]byte, 1025)
	if c.PutForSite(site, key("/"), e) {
		t.Fatal("PutForSite harusnya false untuk body > 1KB")
	}
	if _, ok := c.Get(site.ID, key("/")); ok {
		t.Fatal("Get harusnya miss")
	}
}

// Respons dengan Set-Cookie tidak disimpan.
func TestSetCookieTidakDisimpan(t *testing.T) {
	c := New()
	site := siteCache()
	e := entry("x")
	e.Header.Set("Set-Cookie", "a=b")
	if c.PutForSite(site, key("/"), e) {
		t.Fatal("respons Set-Cookie jangan disimpan")
	}
}

// Cache-Control: private / no-store tidak disimpan.
func TestPrivateNoStoreTidakDisimpan(t *testing.T) {
	c := New()
	site := siteCache()
	for _, cc := range []string{"private, max-age=60", "no-store", "no-cache"} {
		e := entry("x")
		e.Header.Set("Cache-Control", cc)
		if c.PutForSite(site, key("/p"), e) {
			t.Fatalf("Cache-Control %q jangan disimpan", cc)
		}
	}
}

// max-age respons yang lebih kecil dari TTL site dihormati.
func TestMaxAgeDihormati(t *testing.T) {
	c := New()
	site := siteCache()
	e := entry("x")
	e.Header.Set("Cache-Control", "max-age=0")
	if c.PutForSite(site, key("/"), e) {
		t.Fatal("max-age=0 harusnya tidak disimpan")
	}
}

// TTL kedaluwarsa.
func TestTTLKedaluwarsa(t *testing.T) {
	c := New()
	site := siteCache()
	site.CacheTTL = 1
	k := MakeKey("s1", "GET", "x.test", "/", "")
	c.PutForSite(site, k, entry("x"))
	if _, ok := c.Get(site.ID, k); !ok {
		t.Fatal("harus HIT sebelum kedaluwarsa")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok := c.Get(site.ID, k); ok {
		t.Fatal("harus MISS setelah TTL kedaluwarsa")
	}
}

// Batas entri: evict yang tertua.
func TestEvictTertua(t *testing.T) {
	c := New()
	site := siteCache()
	site.CacheMaxEntries = 3
	for i := 0; i < 5; i++ {
		k := MakeKey("s1", "GET", "x.test", fmt.Sprintf("/p%d", i), "")
		if !c.PutForSite(site, k, entry("x")) {
			t.Fatal("PutForSite gagal")
		}
	}
	if s := c.Stats("s1"); s.Entries != 3 {
		t.Fatalf("entries harusnya 3, dapat %d", s.Entries)
	}
	// yang tertua (/p0, /p1) ter-evict; yang terbaru bertahan
	if _, ok := c.Get("s1", MakeKey("s1", "GET", "x.test", "/p0", "")); ok {
		t.Fatal("/p0 (tertua) harusnya ter-evict")
	}
	if _, ok := c.Get("s1", MakeKey("s1", "GET", "x.test", "/p4", "")); !ok {
		t.Fatal("/p4 (terbaru) harusnya masih ada")
	}
}

// Purge per URL dan per site.
func TestPurge(t *testing.T) {
	c := New()
	site := siteCache()
	c.PutForSite(site, key("/a"), entry("a"))
	c.PutForSite(site, key("/b"), entry("b"))
	if n := c.Purge("s1", "/a"); n != 1 {
		t.Fatalf("purge /a harus hapus 1, dapat %d", n)
	}
	if _, ok := c.Get("s1", key("/a")); ok {
		t.Fatal("/a harusnya sudah terhapus")
	}
	if _, ok := c.Get("s1", key("/b")); !ok {
		t.Fatal("/b harusnya masih ada")
	}
	if n := c.Purge("s1", ""); n != 1 {
		t.Fatalf("purge semua harus hapus 1, dapat %d", n)
	}
	if s := c.Stats("s1"); s.Entries != 0 {
		t.Fatalf("entries harusnya 0, dapat %d", s.Entries)
	}
}

// Statistik hit ratio.
func TestStatsRatio(t *testing.T) {
	c := New()
	site := siteCache()
	c.PutForSite(site, key("/s"), entry("s"))
	c.Get("s1", key("/s"))    // hit
	c.Get("s1", key("/lain")) // miss
	s := c.Stats("s1")
	if s.Hits != 1 || s.Misses != 1 {
		t.Fatalf("hits=%d misses=%d, mau 1 dan 1", s.Hits, s.Misses)
	}
	if s.HitRatio != 0.5 {
		t.Fatalf("hit_ratio=%v, mau 0.5", s.HitRatio)
	}
}

// Put mentah memakai ttlSeconds dan batas default.
func TestPutMentah(t *testing.T) {
	c := New()
	c.Put("s1", "k1", entry("x"), 60)
	e, ok := c.Get("s1", "k1")
	if !ok || string(e.Body) != "x" {
		t.Fatal("Put/Get mentah gagal")
	}
	// namespace siteID terpisah
	if _, ok := c.Get("s2", "k1"); ok {
		t.Fatal("siteID berbeda jangan berbagi entry")
	}
	// objek raksasa ditolak
	e2 := entry("y")
	e2.Body = make([]byte, 3*1024*1024)
	c.Put("s1", "k2", e2, 60)
	if _, ok := c.Get("s1", "k2"); ok {
		t.Fatal("body > 2048KB jangan disimpan")
	}
}
