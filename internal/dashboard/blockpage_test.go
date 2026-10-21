package dashboard

// Test API halaman blokir kustom: GET/POST /api/block-page.

import "testing"

func TestBlockPageAPI(t *testing.T) {
	s := newTestSetup(t, testHash(t))

	if code, _ := s.doJSON(t, "GET", "/api/block-page", nil, ""); code != 401 {
		t.Fatalf("tanpa token: code=%d, mau 401", code)
	}
	code, m := s.doJSON(t, "GET", "/api/block-page", nil, "tok-test")
	if code != 200 || m["html"] != "" || m["is_custom"] != false {
		t.Fatalf("awal: code=%d body=%v", code, m)
	}
	const tpl = "<h1>Diblokir {{IP}}</h1>"
	code, m = s.doJSON(t, "POST", "/api/block-page",
		map[string]any{"html": tpl}, "tok-test")
	if code != 200 || m["is_custom"] != true {
		t.Fatalf("simpan: code=%d body=%v", code, m)
	}
	code, m = s.doJSON(t, "GET", "/api/block-page", nil, "tok-test")
	if code != 200 || m["html"] != tpl || m["is_custom"] != true {
		t.Fatalf("setelah simpan: code=%d body=%v", code, m)
	}
	code, m = s.doJSON(t, "POST", "/api/block-page",
		map[string]any{"html": ""}, "tok-test")
	if code != 200 || m["is_custom"] != false {
		t.Fatalf("reset: code=%d body=%v", code, m)
	}
	code, m = s.doJSON(t, "GET", "/api/block-page", nil, "tok-test")
	if code != 200 || m["html"] != "" || m["is_custom"] != false {
		t.Fatalf("setelah reset: code=%d body=%v", code, m)
	}
}
