// Package cloudflare adalah konektor Cloudflare: statistik analytics +
// purge cache via API. API token tidak pernah ke browser — semua panggilan
// di-proxy server-side oleh dashboard. Merupakan port dari
// perisai/cloudflare.py (Python).
package cloudflare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// APIBase adalah base URL Cloudflare API v4. Variabel (bukan konstanta) agar
// test bisa mengarahkannya ke httptest server.
var APIBase = "https://api.cloudflare.com/client/v4"

// HTTPTimeout adalah batas waktu HTTP per panggilan (sesuai Python: 15 dtk).
var HTTPTimeout = 15 * time.Second

// OfficialIPRanges adalah daftar IP range resmi Cloudflare (untuk
// trusted_proxies), disalin persis dari config.example.yaml versi Python
// (https://www.cloudflare.com/ips/).
var OfficialIPRanges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// Zone adalah satu zone Cloudflare (id, name) — sesuai respons GET /zones.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Stats adalah statistik analytics satu zone — key JSON cocok dengan yang
// dipakai dashboard Python (endpoint /api/cf/stats -> UI).
type Stats struct {
	Requests    int64   `json:"requests"`
	Threats     int64   `json:"threats"`
	CachedPct   float64 `json:"cached_pct"`
	BandwidthMB float64 `json:"bandwidth_mb"`
	UpdatedAt   int64   `json:"updated_at"`
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Message string `json:"message"`
}

// apiCall memanggil Cloudflare API dan mengembalikan envelope JSON.
func apiCall(apiToken, method, path string, query url.Values, body any) (cfEnvelope, error) {
	var env cfEnvelope
	if apiToken == "" {
		return env, errors.New("API token Cloudflare belum dikonfigurasi")
	}

	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return env, err
		}
		rdr = bytes.NewReader(buf)
	}
	u := APIBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return env, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return env, fmt.Errorf("CF API error: %w", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return env, fmt.Errorf("CF API error: gagal memparse respons: %w", err)
	}
	return env, nil
}

// cfErrMsg merangkum errors[] dari respons API.
func cfErrMsg(env cfEnvelope) error {
	if len(env.Errors) == 0 {
		return errors.New("CF API error: unknown")
	}
	msgs := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		msgs = append(msgs, e.Message)
	}
	return errors.New(joinNonEmpty(msgs, "; "))
}

func joinNonEmpty(parts []string, sep string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			p = "?"
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}

type cfVerifyResult struct {
	ID string `json:"id"`
}

type cfZoneListResult []Zone

// VerifyToken mengecek validitas API token (GET /user/tokens/verify).
func VerifyToken(apiToken string) (bool, error) {
	env, err := apiCall(apiToken, http.MethodGet, "/user/tokens/verify", nil, nil)
	if err != nil {
		return false, err
	}
	if !env.Success {
		return false, cfErrMsg(env)
	}
	return true, nil
}

// ListZones mengambil daftar zone akun (GET /zones) — hanya id & name.
func ListZones(apiToken string) ([]Zone, error) {
	env, err := apiCall(apiToken, http.MethodGet, "/zones", nil, nil)
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, cfErrMsg(env)
	}
	var zones cfZoneListResult
	if len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, &zones); err != nil {
			return nil, err
		}
	}
	return []Zone(zones), nil
}

// ZoneStats mengambil statistik analytics dashboard satu zone.
// Mirip versi Python: GET /zones/{id}/analytics/dashboard?since=-<minutes>.
func ZoneStats(apiToken, zoneID string, sinceMinutes int) (Stats, error) {
	var st Stats
	if apiToken == "" {
		return st, errors.New("API token Cloudflare belum dikonfigurasi")
	}
	if zoneID == "" {
		return st, errors.New("zone_id belum dipetakan untuk site ini")
	}

	q := url.Values{"since": {strconv.Itoa(-abs(sinceMinutes))}}
	env, err := apiCall(apiToken, http.MethodGet,
		"/zones/"+zoneID+"/analytics/dashboard", q, nil)
	if err != nil {
		return st, err
	}
	if !env.Success {
		return st, cfErrMsg(env)
	}

	var res struct {
		Totals struct {
			Requests  map[string]float64 `json:"requests"`
			Threats   map[string]float64 `json:"threats"`
			Bandwidth map[string]float64 `json:"bandwidth"`
		} `json:"totals"`
	}
	if len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, &res); err != nil {
			return st, err
		}
	}
	all := res.Totals.Requests["all"]
	cached := res.Totals.Requests["cached"]
	st.Requests = int64(all)
	st.Threats = int64(res.Totals.Threats["all"])
	st.CachedPct = math.Round(cached/math.Max(1, all)*100*10) / 10
	st.BandwidthMB = math.Round(res.Totals.Bandwidth["all"]/1024/1024*100) / 100
	st.UpdatedAt = time.Now().Unix()
	return st, nil
}

// PurgeCache menghapus seluruh cache satu zone
// (POST /zones/{id}/purge_cache {purge_everything:true}).
func PurgeCache(apiToken, zoneID string) error {
	if apiToken == "" {
		return errors.New("API token Cloudflare belum dikonfigurasi")
	}
	if zoneID == "" {
		return errors.New("zone_id belum dipetakan untuk site ini")
	}
	env, err := apiCall(apiToken, http.MethodPost,
		"/zones/"+zoneID+"/purge_cache", nil,
		map[string]any{"purge_everything": true})
	if err != nil {
		return err
	}
	if !env.Success {
		return cfErrMsg(env)
	}
	return nil
}

// PurgeFiles menghapus cache untuk daftar URL/file tertentu di satu zone
// (POST /zones/{id}/purge_cache {"files": [...]}). Setara purge_cache(urls)
// di cloudflare.py Python.
func PurgeFiles(apiToken, zoneID string, urls []string) error {
	if apiToken == "" {
		return errors.New("API token Cloudflare belum dikonfigurasi")
	}
	if zoneID == "" {
		return errors.New("zone_id belum dipetakan untuk site ini")
	}
	env, err := apiCall(apiToken, http.MethodPost,
		"/zones/"+zoneID+"/purge_cache", nil,
		map[string]any{"files": urls})
	if err != nil {
		return err
	}
	if !env.Success {
		return cfErrMsg(env)
	}
	return nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
