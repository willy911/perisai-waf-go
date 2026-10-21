package dashboard

// Test API Dynamic Protection per-site: toggle via dashboard dan flag
// yang tampil di JSON site.

import "testing"

func TestSiteDynamicProtectionAPI(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "POST", "/api/sites", map[string]any{
		"domain": "dyn.test", "upstream_host": "127.0.0.1",
		"upstream_port": 9002,
	}, "tok-test")
	if code != 200 {
		t.Fatalf("buat site: code=%d body=%v", code, m)
	}
	sid, _ := m["id"].(string)
	p := "/api/sites/" + sid + "/dynamic-protection"

	if code, _ := s.doJSON(t, "POST", p, map[string]any{"enabled": true}, ""); code != 401 {
		t.Fatalf("tanpa token: code=%d, mau 401", code)
	}
	code, m = s.doJSON(t, "POST", p, map[string]any{"enabled": true}, "tok-test")
	if code != 200 || m["dynamic_protection"] != true {
		t.Fatalf("aktifkan: code=%d body=%v", code, m)
	}
	code, m = s.doJSON(t, "GET", "/api/sites/"+sid, nil, "tok-test")
	if code != 200 || m["dynamic_protection"] != true {
		t.Fatalf("get site: code=%d dyn=%v", code, m["dynamic_protection"])
	}
	code, m = s.doJSON(t, "POST", p, map[string]any{"enabled": false}, "tok-test")
	if code != 200 || m["dynamic_protection"] != false {
		t.Fatalf("matikan: code=%d body=%v", code, m)
	}
	if code, _ := s.doJSON(t, "POST", "/api/sites/tidakada/dynamic-protection",
		map[string]any{"enabled": true}, "tok-test"); code != 404 {
		t.Fatalf("site asing: code=%d, mau 404", code)
	}
}
