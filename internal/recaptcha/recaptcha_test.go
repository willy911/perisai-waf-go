// Test recaptcha: meniru respons Google via httptest (tanpa hit google asli).
// Vektor dari tests/test_recaptcha.py (Python).
package recaptcha

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGoogle menjalankan httptest server yang meniru siteverify.
func fakeGoogle(t *testing.T, resp map[string]any) (seen map[string]string) {
	t.Helper()
	seen = map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("gagal parse form: %v", err)
		}
		seen["secret"] = r.FormValue("secret")
		seen["response"] = r.FormValue("response")
		seen["remoteip"] = r.FormValue("remoteip")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(func() {
		srv.Close()
		VerifyURL = "https://www.google.com/recaptcha/api/siteverify"
	})
	VerifyURL = srv.URL
	return seen
}

func TestVerifyV2OK(t *testing.T) {
	// vektor Python: success=true -> ok
	seen := fakeGoogle(t, map[string]any{"success": true})
	ok, err := Verify("sec", "tok", "1.2.3.4", 0)
	if !ok || err != nil {
		t.Fatalf("harusnya ok: %v", err)
	}
	if seen["secret"] != "sec" || seen["response"] != "tok" || seen["remoteip"] != "1.2.3.4" {
		t.Fatalf("form terkirim salah: %v", seen)
	}
}

func TestVerifyV2Ditolak(t *testing.T) {
	// vektor Python: success=false + error-codes -> ok=False, pesan berisi kode
	fakeGoogle(t, map[string]any{
		"success": false, "error-codes": []string{"invalid-input-secret"},
	})
	ok, err := Verify("sec", "tok", "", 0)
	if ok {
		t.Fatal("harusnya tidak ok")
	}
	if err == nil || !strings.Contains(err.Error(), "invalid-input-secret") {
		t.Fatalf("pesan harus berisi kode error: %v", err)
	}
}

func TestVerifyV3ScoreOK(t *testing.T) {
	fakeGoogle(t, map[string]any{"success": true, "score": 0.9})
	ok, err := Verify("sec", "tok", "", 0.5)
	if !ok || err != nil {
		t.Fatalf("skor 0.9 >= 0.5 harusnya ok: %v", err)
	}
}

func TestVerifyV3ScoreRendah(t *testing.T) {
	fakeGoogle(t, map[string]any{"success": true, "score": 0.3})
	ok, err := Verify("sec", "tok", "", 0.5)
	if ok {
		t.Fatal("skor 0.3 < 0.5 harusnya tidak ok")
	}
	if err == nil {
		t.Fatal("harusnya ada pesan error skor")
	}
}

func TestVerifyTanpaSecret(t *testing.T) {
	// vektor Python: secret kosong -> (False, pesan berisi "secret")
	ok, err := Verify("", "tok", "", 0)
	if ok || err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("harusnya gagal dengan pesan secret: %v", err)
	}
}

func TestVerifyTokenKosong(t *testing.T) {
	// vektor Python: token kosong -> (False, ...)
	ok, err := Verify("sec", "", "", 0)
	if ok || err == nil {
		t.Fatal("harusnya gagal untuk token kosong")
	}
}

func TestVerifyGagalHubungi(t *testing.T) {
	VerifyURL = "http://127.0.0.1:1/nonexistent"
	t.Cleanup(func() {
		VerifyURL = "https://www.google.com/recaptcha/api/siteverify"
	})
	ok, err := Verify("sec", "tok", "", 0)
	if ok || err == nil {
		t.Fatal("harusnya gagal bila server tak terjangkau")
	}
}
