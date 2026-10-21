package dashboard

// Test API Authentication Challenge per-site: atur password & toggle via
// dashboard; hash tidak pernah bocor ke respons JSON.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSiteAuthChallengeAPI(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	code, m := s.doJSON(t, "POST", "/api/sites", map[string]any{
		"domain": "kunci.test", "upstream_host": "127.0.0.1",
		"upstream_port": 9001,
	}, "tok-test")
	if code != 200 {
		t.Fatalf("buat site: code=%d body=%v", code, m)
	}
	sid, _ := m["id"].(string)
	if sid == "" {
		t.Fatalf("respons buat site tanpa id: %v", m)
	}
	p := "/api/sites/" + sid + "/auth-challenge"

	// Tanpa token -> 401.
	if code, _ := s.doJSON(t, "POST", p, map[string]any{"enabled": true}, ""); code != 401 {
		t.Fatalf("tanpa token: code=%d, mau 401", code)
	}

	// Mengaktifkan tanpa password -> 400.
	code, m = s.doJSON(t, "POST", p, map[string]any{"enabled": true}, "tok-test")
	if code != 400 {
		t.Fatalf("aktifkan tanpa password: code=%d body=%v, mau 400", code, m)
	}

	// Atur password + aktifkan -> ok, set=true.
	code, m = s.doJSON(t, "POST", p, map[string]any{
		"enabled": true, "password": "rahasia123",
	}, "tok-test")
	if code != 200 || m["ok"] != true || m["auth_challenge_set"] != true ||
		m["auth_challenge_enabled"] != true {
		t.Fatalf("atur password: code=%d body=%v", code, m)
	}

	// GET site: hash tidak boleh ada; flag set/enabled benar.
	code, m = s.doJSON(t, "GET", "/api/sites/"+sid, nil, "tok-test")
	if code != 200 {
		t.Fatalf("get site: code=%d", code)
	}
	if _, ada := m["auth_challenge_hash"]; ada {
		t.Fatal("auth_challenge_hash bocor ke JSON site")
	}
	if m["auth_challenge_set"] != true || m["auth_challenge_enabled"] != true {
		t.Fatalf("flag site salah: %v", m)
	}

	// Daftar site juga bersih dari hash.
	_, raw := s.do(t, "GET", "/api/sites", nil, "tok-test")
	if strings.Contains(string(raw), "auth_challenge_hash") ||
		strings.Contains(string(raw), "pbkdf2") {
		t.Fatalf("hash bocor di daftar site: %s", raw)
	}
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) != 1 {
		t.Fatalf("daftar site: err=%v len=%d", err, len(list))
	}
	if list[0]["auth_challenge_set"] != true {
		t.Fatalf("flag set di daftar salah: %v", list[0])
	}

	// Matikan tanpa password -> tetap ok dan password tersimpan (set).
	code, m = s.doJSON(t, "POST", p, map[string]any{"enabled": false}, "tok-test")
	if code != 200 || m["auth_challenge_enabled"] != false ||
		m["auth_challenge_set"] != true {
		t.Fatalf("matikan: code=%d body=%v", code, m)
	}

	// Site tak dikenal -> 404.
	if code, _ := s.doJSON(t, "POST", "/api/sites/tidakada/auth-challenge",
		map[string]any{"enabled": true}, "tok-test"); code != 404 {
		t.Fatalf("site asing: code=%d, mau 404", code)
	}
}
