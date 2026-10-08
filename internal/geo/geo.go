// Package geo menyediakan resolusi GeoIP untuk peta serangan.
//
// Urutan fallback persis seperti Python (perisai/geo.py):
// file GeoLite2-City.mmdb (bila ada di mmdb_path atau data_dir) ->
// API gratis ip-api.com (dengan cache SQLite) -> kosong.
// IP privat/loopback selalu dilewati tanpa query.
//
// Merupakan port dari perisai/geo.py (Python).
package geo

import (
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/storage"
)

// defaultAPIURL adalah endpoint API gratis ip-api.com,
// persis seperti URL di geo.py Python.
const defaultAPIURL = "http://ip-api.com/json"

// apiTimeout mengikuti spesifikasi port Go (~5 detik).
const apiTimeout = 5 * time.Second

// Geo adalah resolver GeoIP yang dipilih berdasarkan GeoConfig.
type Geo struct {
	cfg     config.GeoConfig
	dataDir string
	store   *storage.Storage

	// apiBaseURL bisa di-override di test dengan httptest.
	apiBaseURL string
	client     *http.Client

	// pembaca MMDB dibuka lazy (sekali saja), agar New tetap tanpa error
	// seperti make_resolver di Python yang menelan error buka file.
	mmdbOnce   sync.Once
	mmdbReader *maxminddb.Reader

	// ccCache adalah cache in-memory kode negara dari API (hemat kuota
	// ip-api.com yang rate-limited); entri kedaluwarsa setelah ccTTL.
	ccMu    sync.Mutex
	ccCache map[string]ccEntry
}

type ccEntry struct {
	code    string
	expires time.Time
}

const ccTTL = time.Hour

// New membuat resolver GeoIP dari config, data dir, dan storage cache.
func New(cfg config.GeoConfig, dataDir string, store *storage.Storage) *Geo {
	g := &Geo{
		cfg:        cfg,
		dataDir:    dataDir,
		store:      store,
		apiBaseURL: defaultAPIURL,
		client:     &http.Client{Timeout: apiTimeout},
		ccCache:    make(map[string]ccEntry),
	}
	if cfg.APIURL != "" {
		g.apiBaseURL = cfg.APIURL
	}
	return g
}

// Lookup mengembalikan country, city, lat, lon untuk sebuah IP.
// Bila gagal atau fitur mati: string kosong & 0, tanpa error fatal.
func (g *Geo) Lookup(ip string) (country, city string, lat, lon float64) {
	if !g.cfg.Enabled || g.cfg.Provider == "off" {
		return "", "", 0, 0
	}
	if !isPublic(ip) {
		return "", "", 0, 0
	}
	mmdb := g.cfg.MMDBPath
	if mmdb == "" {
		mmdb = filepath.Join(g.dataDir, "GeoLite2-City.mmdb")
	}
	if (g.cfg.Provider == "auto" || g.cfg.Provider == "mmdb") && fileExists(mmdb) {
		if c, ci, la, lo, ok := g.lookupMMDB(ip); ok {
			return c, ci, la, lo
		}
	}
	if g.cfg.Provider == "auto" || g.cfg.Provider == "api" {
		if c, ci, la, lo, ok := g.lookupAPI(ip); ok {
			return c, ci, la, lo
		}
	}
	return "", "", 0, 0
}

// reservedPrefixes adalah rentang reserved yang tidak dicakup IsGlobalUnicast
// Go (padanan is_reserved di Python).
var reservedPrefixes []netip.Prefix

func init() {
	for _, p := range []string{
		"0.0.0.0/8",    // software scope (is_reserved di Python)
		"192.0.0.0/24", // penugasan protokol IETF
		"240.0.0.0/4",  // reserved (is_reserved di Python)
		"100::/64",     // discard-only (is_reserved di Python)
	} {
		if pref, err := netip.ParsePrefix(p); err == nil {
			reservedPrefixes = append(reservedPrefixes, pref)
		}
	}
}

// isPublic membuang IP privat/loopback/reserved/multicast,
// padanan _is_public di Python.
//
// Catatan: net.IP.IsGlobalUnicast ala Go TIDAK mengecualikan IP privat,
// jadi cek is_private/loopback/multicast/reserved dilakukan eksplisit.
func isPublic(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsMulticast() ||
		parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() {
		return false
	}
	addr, ok := netip.AddrFromSlice(parsed.To16())
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, pref := range reservedPrefixes {
		if pref.Contains(addr) {
			return false
		}
	}
	return addr.IsGlobalUnicast()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// -- resolver MMDB --------------------------------------------------------

// mmdbCity adalah struktur hasil lookup GeoLite2-City.
type mmdbCity struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names   map[string]string `maxminddb:"names"`
		ISOCode string            `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// CountryCode mengembalikan kode negara ISO 3166-1 alpha-2 (uppercase,
// mis. "ID") untuk sebuah IP, atau "" bila tidak diketahui / fitur mati.
// Dipakai untuk geo-blocking: "" berarti fail-open (jangan blokir).
func (g *Geo) CountryCode(ip string) string {
	if !g.cfg.Enabled || g.cfg.Provider == "off" {
		return ""
	}
	if !isPublic(ip) {
		return ""
	}
	if code := g.countryCodeMMDB(ip); code != "" {
		return code
	}
	if g.cfg.Provider == "mmdb" {
		return ""
	}
	return g.countryCodeAPI(ip)
}

// countryCodeMMDB mengambil ISO code dari file MMDB lokal (bila ada).
func (g *Geo) countryCodeMMDB(ip string) string {
	mmdb := g.cfg.MMDBPath
	if mmdb == "" {
		mmdb = filepath.Join(g.dataDir, "GeoLite2-City.mmdb")
	}
	if !(g.cfg.Provider == "auto" || g.cfg.Provider == "mmdb") || !fileExists(mmdb) {
		return ""
	}
	r := g.openMMDB()
	if r == nil {
		return ""
	}
	var rec mmdbCity
	if err := r.Lookup(net.ParseIP(ip), &rec); err != nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(rec.Country.ISOCode))
}

// countryCodeAPI mengambil ISO code via API (dengan cache in-memory 1 jam).
func (g *Geo) countryCodeAPI(ip string) string {
	g.ccMu.Lock()
	if e, ok := g.ccCache[ip]; ok && time.Now().Before(e.expires) {
		code := e.code
		g.ccMu.Unlock()
		return code
	}
	g.ccMu.Unlock()

	code := ""
	url := g.apiBaseURL + "/" + ip + "?fields=status,countryCode"
	resp, err := g.client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		var ar struct {
			Status      string `json:"status"`
			CountryCode string `json:"countryCode"`
		}
		if body, err := io.ReadAll(io.LimitReader(resp.Body, 4096)); err == nil {
			if json.Unmarshal(body, &ar) == nil && ar.Status == "success" {
				code = strings.ToUpper(strings.TrimSpace(ar.CountryCode))
			}
		}
	}
	// Cache juga hasil kosong (negatif) agar IP tak dikenal tidak
	// menghantam API berulang-ulang.
	g.ccMu.Lock()
	g.ccCache[ip] = ccEntry{code: code, expires: time.Now().Add(ccTTL)}
	// Batasi ukuran cache oportunistik.
	if len(g.ccCache) > 10000 {
		for k, e := range g.ccCache {
			if time.Now().After(e.expires) {
				delete(g.ccCache, k)
			}
		}
	}
	g.ccMu.Unlock()
	return code
}

// mmdbName mengambil nama dengan locale "en" dulu (default geoip2 Python),
// fallback ke nama apa pun yang tersedia.
func mmdbName(names map[string]string) string {
	if n, ok := names["en"]; ok && n != "" {
		return n
	}
	for _, n := range names {
		if n != "" {
			return n
		}
	}
	return ""
}

// mmdbPath mengembalikan path file MMDB yang dipakai (mmdb_path config
// atau default dataDir/GeoLite2-City.mmdb).
func (g *Geo) mmdbPath() string {
	if g.cfg.MMDBPath != "" {
		return g.cfg.MMDBPath
	}
	return filepath.Join(g.dataDir, "GeoLite2-City.mmdb")
}

// openMMDB membuka reader MMDB sekali saja; kegagalan dicatat sebagai nil
// agar Lookup jatuh ke API (seperti try/except pass di make_resolver Python).
func (g *Geo) openMMDB() *maxminddb.Reader {
	g.mmdbOnce.Do(func() {
		r, err := maxminddb.Open(g.mmdbPath())
		if err == nil {
			g.mmdbReader = r
		}
	})
	return g.mmdbReader
}

func (g *Geo) lookupMMDB(ip string) (country, city string, lat, lon float64, ok bool) {
	r := g.openMMDB()
	if r == nil {
		return "", "", 0, 0, false
	}
	var rec mmdbCity
	if err := r.Lookup(net.ParseIP(ip), &rec); err != nil {
		return "", "", 0, 0, false
	}
	country = mmdbName(rec.Country.Names)
	city = mmdbName(rec.City.Names)
	if rec.Location.Latitude != nil {
		lat = *rec.Location.Latitude
	}
	if rec.Location.Longitude != nil {
		lon = *rec.Location.Longitude
	}
	return country, city, lat, lon, true
}

// -- resolver API ip-api.com ----------------------------------------------

type apiResponse struct {
	Status  string   `json:"status"`
	Country string   `json:"country"`
	City    string   `json:"city"`
	Lat     *float64 `json:"lat"`
	Lon     *float64 `json:"lon"`
}

func (g *Geo) lookupAPI(ip string) (country, city string, lat, lon float64, ok bool) {
	// Cek cache dulu, seperti ApiResolver.resolve di Python.
	if g.store != nil {
		if cached, err := g.store.GeoGet(ip); err == nil && cached != nil {
			country = toStr(cached["country"])
			city = toStr(cached["city"])
			lat = toF64(cached["lat"])
			lon = toF64(cached["lon"])
			return country, city, lat, lon, true
		} else if err != nil && err != sql.ErrNoRows {
			// error DB selain "tak ada baris" diabaikan, lanjut ke API
		}
	}

	// URL persis seperti geo.py Python:
	// http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon
	url := g.apiBaseURL + "/" + ip + "?fields=status,country,city,lat,lon"
	resp, err := g.client.Get(url)
	if err != nil {
		return "", "", 0, 0, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", 0, 0, false
	}
	var data apiResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return "", "", 0, 0, false
	}
	if data.Status != "success" {
		return "", "", 0, 0, false
	}

	country, city = data.Country, data.City
	if data.Lat != nil {
		lat = *data.Lat
	}
	if data.Lon != nil {
		lon = *data.Lon
	}

	// Simpan hasil sukses ke cache (lat/lon nil -> NULL seperti Python).
	if g.store != nil {
		_ = g.store.GeoSet(ip, country, city, data.Lat, data.Lon)
	}
	return country, city, lat, lon, true
}

// -- konversi nilai dari map cache ----------------------------------------

func toStr(v any) string {
	s, _ := v.(string)
	return s
}

func toF64(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int64:
		return float64(t)
	case int:
		return float64(t)
	}
	return 0
}
