package geo

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/storage"
)

// newTestStore membuat storage SQLite di direktori sementara.
func newTestStore(t *testing.T) *storage.Storage {
	t.Helper()
	s, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// newTestGeo membuat Geo dengan provider api dan base URL mock.
func newTestGeo(t *testing.T, s *storage.Storage, baseURL string) *Geo {
	t.Helper()
	g := New(config.GeoConfig{Enabled: true, Provider: "api"}, t.TempDir(), s)
	g.apiBaseURL = baseURL
	return g
}

func TestOffProviderReturnsEmpty(t *testing.T) {
	s := newTestStore(t)
	for _, cfg := range []config.GeoConfig{
		{Enabled: true, Provider: "off"},
		{Enabled: false, Provider: "api"},
	} {
		g := New(cfg, t.TempDir(), s)
		c, ci, la, lo := g.Lookup("8.8.8.8")
		if c != "" || ci != "" || la != 0 || lo != 0 {
			t.Errorf("cfg %+v: dapat (%q,%q,%v,%v), ingin kosong", cfg, c, ci, la, lo)
		}
	}
}

func TestPrivateIPSkippedWithoutHTTP(t *testing.T) {
	// Server yang gagalkan test bila disentuh: IP privat tidak boleh query API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API tidak boleh di-query untuk IP privat")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := newTestStore(t)
	g := newTestGeo(t, s, srv.URL)
	for _, ip := range []string{"192.168.1.1", "127.0.0.1", "10.0.0.5", "fc00::1", "bukan-ip"} {
		c, ci, la, lo := g.Lookup(ip)
		if c != "" || ci != "" || la != 0 || lo != 0 {
			t.Errorf("ip %s: dapat (%q,%q,%v,%v), ingin kosong", ip, c, ci, la, lo)
		}
	}
}

func TestAPISuccessAndCached(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// URL persis seperti Python: /{ip}?fields=status,country,city,lat,lon
		if got := r.URL.RawQuery; got != "fields=status,country,city,lat,lon" {
			t.Errorf("query = %q, ingin fields=status,country,city,lat,lon", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","country":"Indonesia","city":"Jakarta","lat":-6.2,"lon":106.8}`))
	}))
	defer srv.Close()

	s := newTestStore(t)
	g := newTestGeo(t, s, srv.URL)

	c, ci, la, lo := g.Lookup("8.8.8.8")
	if c != "Indonesia" || ci != "Jakarta" || la != -6.2 || lo != 106.8 {
		t.Fatalf("dapat (%q,%q,%v,%v), ingin (Indonesia,Jakarta,-6.2,106.8)", c, ci, la, lo)
	}
	if hits.Load() != 1 {
		t.Fatalf("panggilan HTTP = %d, ingin 1", hits.Load())
	}

	// Panggilan kedua harus dari cache, tanpa hit HTTP lagi.
	c, ci, la, lo = g.Lookup("8.8.8.8")
	if c != "Indonesia" || ci != "Jakarta" || la != -6.2 || lo != 106.8 {
		t.Fatalf("cache: dapat (%q,%q,%v,%v)", c, ci, la, lo)
	}
	if hits.Load() != 1 {
		t.Fatalf("panggilan HTTP setelah cache = %d, ingin tetap 1", hits.Load())
	}

	// Verifikasi tersimpan di cache storage.
	cached, err := s.GeoGet("8.8.8.8")
	if err != nil {
		t.Fatalf("GeoGet: %v", err)
	}
	if cached["country"] != "Indonesia" || cached["city"] != "Jakarta" {
		t.Fatalf("isi cache: %v", cached)
	}
}

func TestAPIFailureReturnsEmpty(t *testing.T) {
	// status=fail dari ip-api.com
	srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"fail","message":"private range"}`))
	}))
	defer srvFail.Close()

	// server mati: koneksi gagal
	srvDead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srvDead.URL
	srvDead.Close()

	for _, url := range []string{srvFail.URL, deadURL} {
		s := newTestStore(t)
		g := newTestGeo(t, s, url)
		c, ci, la, lo := g.Lookup("1.1.1.1")
		if c != "" || ci != "" || la != 0 || lo != 0 {
			t.Errorf("url %s: dapat (%q,%q,%v,%v), ingin kosong", url, c, ci, la, lo)
		}
	}
}

func TestCacheHitServedWithoutHTTP(t *testing.T) {
	// Pre-populasi cache langsung via storage.
	s := newTestStore(t)
	lat, lon := -7.25, 112.75
	if err := s.GeoSet("203.0.113.10", "Indonesia", "Surabaya", &lat, &lon); err != nil {
		t.Fatalf("GeoSet: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API tidak boleh di-query bila cache ada")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	g := newTestGeo(t, s, srv.URL)
	c, ci, la, lo := g.Lookup("203.0.113.10")
	if c != "Indonesia" || ci != "Surabaya" || la != -7.25 || lo != 112.75 {
		t.Fatalf("dapat (%q,%q,%v,%v), ingin (Indonesia,Surabaya,-7.25,112.75)", c, ci, la, lo)
	}
}

func TestAutoProviderFallsBackToAPIWithoutMMDB(t *testing.T) {
	// provider "auto" tanpa file MMDB -> pakai API.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","country":"Singapore","city":"Singapore","lat":1.35,"lon":103.82}`))
	}))
	defer srv.Close()

	s := newTestStore(t)
	g := New(config.GeoConfig{Enabled: true, Provider: "auto"}, t.TempDir(), s)
	g.apiBaseURL = srv.URL

	c, ci, la, lo := g.Lookup("8.8.4.4")
	if c != "Singapore" || ci != "Singapore" || la != 1.35 || lo != 103.82 {
		t.Fatalf("dapat (%q,%q,%v,%v)", c, ci, la, lo)
	}
	if hits.Load() != 1 {
		t.Fatalf("panggilan HTTP = %d, ingin 1", hits.Load())
	}
}

func TestMMDBProviderWithoutFileReturnsEmpty(t *testing.T) {
	// provider "mmdb" tanpa file (dan tanpa fallback API) -> kosong.
	s := newTestStore(t)
	g := New(config.GeoConfig{Enabled: true, Provider: "mmdb"}, t.TempDir(), s)
	c, ci, la, lo := g.Lookup("8.8.8.8")
	if c != "" || ci != "" || la != 0 || lo != 0 {
		t.Errorf("dapat (%q,%q,%v,%v), ingin kosong", c, ci, la, lo)
	}
}
