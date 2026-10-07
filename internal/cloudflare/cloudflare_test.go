// Test cloudflare: meniru API Cloudflare via httptest.
// Vektor dari tests/test_cloudflare.py (Python).
package cloudflare

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCF menjalankan httptest server yang meniru API Cloudflare.
func fakeCF(t *testing.T, handler func(seen map[string]string, w http.ResponseWriter, r *http.Request)) {
	t.Helper()
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(seen, w, r)
	}))
	t.Cleanup(func() {
		srv.Close()
		APIBase = "https://api.cloudflare.com/client/v4"
	})
	APIBase = srv.URL
}

func checkAuth(t *testing.T, seen map[string]string, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	seen["auth"] = r.Header.Get("Authorization")
	seen["path"] = r.URL.Path
	seen["query"] = r.URL.RawQuery
	if seen["auth"] != "Bearer tok-abc" {
		t.Errorf("header auth salah: %q", seen["auth"])
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTokenOK(t *testing.T) {
	var gotPath string
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, seen, w, r) {
			return
		}
		gotPath = r.URL.Path
		writeJSON(t, w, map[string]any{
			"success": true, "result": map[string]any{"id": "abc", "status": "active"},
		})
	})
	ok, err := VerifyToken("tok-abc")
	if !ok || err != nil {
		t.Fatalf("harusnya ok: %v", err)
	}
	if gotPath != "/user/tokens/verify" {
		t.Fatalf("path salah: %s", gotPath)
	}
}

func TestVerifyTokenGagal(t *testing.T) {
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"success": false,
			"errors":  []map[string]any{{"message": "Invalid token"}},
		})
	})
	ok, err := VerifyToken("tok-salah")
	if ok || err == nil || !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("harusnya gagal dengan pesan: %v", err)
	}
}

func TestListZones(t *testing.T) {
	var gotPath string
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, seen, w, r) {
			return
		}
		gotPath = r.URL.Path
		writeJSON(t, w, map[string]any{
			"success": true,
			"result": []map[string]any{
				{"id": "zone1", "name": "contoh.test"},
				{"id": "zone2", "name": "a.test"},
			},
		})
	})
	zones, err := ListZones("tok-abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].ID != "zone1" || zones[0].Name != "contoh.test" {
		t.Fatalf("zones tak sesuai: %+v", zones)
	}
	if gotPath != "/zones" {
		t.Fatalf("path salah: %s", gotPath)
	}
}

func TestZoneStats(t *testing.T) {
	var gotPath, gotQuery string
	// vektor Python: totals requests all=1000 cached=750, threats all=12,
	// bandwidth all=10485760 -> requests=1000, threats=12,
	// cached_pct=75.0, bandwidth_mb=10.0
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, seen, w, r) {
			return
		}
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		writeJSON(t, w, map[string]any{
			"success": true,
			"result": map[string]any{"totals": map[string]any{
				"requests":  map[string]any{"all": 1000, "cached": 750},
				"threats":   map[string]any{"all": 12},
				"bandwidth": map[string]any{"all": 10485760},
			}},
		})
	})
	st, err := ZoneStats("tok-abc", "zone9", 1440)
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 1000 {
		t.Errorf("requests = %d, mau 1000", st.Requests)
	}
	if st.Threats != 12 {
		t.Errorf("threats = %d, mau 12", st.Threats)
	}
	if st.CachedPct != 75.0 {
		t.Errorf("cached_pct = %v, mau 75.0", st.CachedPct)
	}
	if st.BandwidthMB != 10.0 {
		t.Errorf("bandwidth_mb = %v, mau 10.0", st.BandwidthMB)
	}
	if st.UpdatedAt <= 0 {
		t.Errorf("updated_at harus terisi, dapat %d", st.UpdatedAt)
	}
	wantPath := "/zones/zone9/analytics/dashboard"
	if gotPath != wantPath {
		t.Errorf("path = %s, mau %s", gotPath, wantPath)
	}
	if !strings.Contains(gotQuery, "since=-1440") {
		t.Errorf("query harus berisi since=-1440: %s", gotQuery)
	}
}

func TestZoneStatsAPIError(t *testing.T) {
	// vektor Python: success=false -> ok=False, pesan berisi "Invalid zone"
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"success": false,
			"errors":  []map[string]any{{"message": "Invalid zone"}},
		})
	})
	_, err := ZoneStats("tok", "bad", 1440)
	if err == nil || !strings.Contains(err.Error(), "Invalid zone") {
		t.Fatalf("harusnya gagal dengan pesan: %v", err)
	}
}

func TestPurgeCache(t *testing.T) {
	// vektor Python: payload {"purge_everything": True}
	var gotPayload map[string]any
	var gotPath string
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, seen, w, r) {
			return
		}
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Errorf("gagal decode payload: %v", err)
		}
		writeJSON(t, w, map[string]any{"success": true, "result": map[string]any{"id": "x"}})
	})
	if err := PurgeCache("tok-abc", "z1"); err != nil {
		t.Fatal(err)
	}
	if gotPayload["purge_everything"] != true {
		t.Fatalf("payload salah: %v", gotPayload)
	}
	if gotPath != "/zones/z1/purge_cache" {
		t.Fatalf("path salah: %s", gotPath)
	}
}

func TestPurgeCacheGagal(t *testing.T) {
	fakeCF(t, func(seen map[string]string, w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"success": false,
			"errors":  []map[string]any{{"message": "zone not found"}},
		})
	})
	if err := PurgeCache("tok", "bad"); err == nil {
		t.Fatal("harusnya gagal")
	}
}

func TestTanpaToken(t *testing.T) {
	// vektor Python: token kosong -> (False, pesan berisi "token")
	if ok, _ := VerifyToken(""); ok {
		t.Error("VerifyToken tanpa token harusnya gagal")
	}
	if _, err := ListZones(""); err == nil {
		t.Error("ListZones tanpa token harusnya gagal")
	}
	if _, err := ZoneStats("", "zone1", 1440); err == nil ||
		!strings.Contains(err.Error(), "token") {
		t.Errorf("ZoneStats tanpa token harusnya gagal dengan pesan token: %v", err)
	}
	if err := PurgeCache("", "zone1"); err == nil {
		t.Error("PurgeCache tanpa token harusnya gagal")
	}
}

func TestTanpaZoneID(t *testing.T) {
	// vektor Python: zone kosong -> (False, pesan berisi "zone_id")
	if _, err := ZoneStats("tok", "", 1440); err == nil ||
		!strings.Contains(err.Error(), "zone_id") {
		t.Errorf("ZoneStats tanpa zone harusnya gagal dengan pesan zone_id: %v", err)
	}
	if err := PurgeCache("tok", ""); err == nil {
		t.Error("PurgeCache tanpa zone harusnya gagal")
	}
}

// OfficialIPRanges harus berisi CIDR valid (persis dari config.example.yaml).
func TestOfficialIPRangesValidCIDR(t *testing.T) {
	if len(OfficialIPRanges) == 0 {
		t.Fatal("OfficialIPRanges kosong")
	}
	for _, cidr := range OfficialIPRanges {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			t.Errorf("CIDR tidak valid: %q: %v", cidr, err)
		}
	}
	if len(OfficialIPRanges) != 22 {
		t.Errorf("jumlah range = %d, mau 22 (sesuai config.example.yaml)",
			len(OfficialIPRanges))
	}
}
