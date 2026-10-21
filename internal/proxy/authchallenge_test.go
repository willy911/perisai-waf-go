package proxy

// Test Authentication Challenge per-site: gerbang password di proxy.
// Pengunjung tanpa cookie valid hanya menerima form; password benar ->
// cookie perisai_auth + 302; cookie valid -> request diteruskan.

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/willy911/perisai-waf/internal/auth"
)

func TestAuthToken(t *testing.T) {
	tok := issueAuthToken("secret", "site-1")
	if !verifyAuthToken("secret", "site-1", tok) {
		t.Fatal("token yang baru diterbitkan harus valid")
	}
	if verifyAuthToken("secret", "site-2", tok) {
		t.Fatal("token tidak boleh berlaku untuk site lain")
	}
	if verifyAuthToken("lain", "site-1", tok) {
		t.Fatal("token tidak boleh valid dengan secret berbeda")
	}
	if verifyAuthToken("secret", "site-1", "") ||
		verifyAuthToken("secret", "site-1", "abc") {
		t.Fatal("token kosong/rusak harus ditolak")
	}
}

func TestAuthChallengeGate(t *testing.T) {
	e := newTestEnv(t, nil)
	hash, err := auth.HashPassword("rahasia123")
	if err != nil {
		t.Fatal(err)
	}
	e.addSite("kunci.test", map[string]any{
		"auth_challenge_enabled": 1,
		"auth_challenge_hash":    hash,
	})
	client := noRedirectClient()
	do := func(method, p string, form url.Values, cookie string) (int, http.Header, string) {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequest(method, e.proxyURL+p, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "kunci.test"
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// 1. Tanpa cookie -> 401 + form login; upstream tidak tersentuh.
	code, _, body := do("GET", "/rahasia?x=1", nil, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("GET tanpa cookie: status=%d, mau 401", code)
	}
	if !strings.Contains(body, `name="password"`) ||
		!strings.Contains(body, `action="`+AuthPath+`"`) ||
		!strings.Contains(body, `value="/rahasia?x=1"`) {
		t.Fatalf("halaman auth tidak lengkap: %q", body)
	}
	if _, _, _, _, _, _, n := e.up.snapshot(); n != 0 {
		t.Fatalf("upstream tersentuh %d kali, mau 0", n)
	}

	// 2. Password salah -> 401 + pesan error, tanpa cookie.
	code, hdr, body := do("POST", AuthPath,
		url.Values{"password": {"salah"}, "next": {"/rahasia"}}, "")
	if code != http.StatusUnauthorized ||
		!strings.Contains(body, "Password salah") {
		t.Fatalf("POST salah: status=%d body=%q", code, body)
	}
	if strings.Contains(hdr.Get("Set-Cookie"), AuthCookieName+"=") {
		t.Fatal("password salah tidak boleh menerbitkan cookie")
	}

	// 3. Password benar -> 302 ke next + cookie HttpOnly.
	code, hdr, _ = do("POST", AuthPath,
		url.Values{"password": {"rahasia123"}, "next": {"/rahasia"}}, "")
	if code != http.StatusFound || hdr.Get("Location") != "/rahasia" {
		t.Fatalf("POST benar: status=%d location=%q", code, hdr.Get("Location"))
	}
	setCookie := hdr.Get("Set-Cookie")
	if !strings.Contains(setCookie, AuthCookieName+"=") ||
		!strings.Contains(setCookie, "HttpOnly") {
		t.Fatalf("Set-Cookie tidak sesuai: %q", setCookie)
	}
	cookie := AuthCookieName + "=" +
		strings.SplitN(strings.SplitN(setCookie, AuthCookieName+"=", 2)[1], ";", 2)[0]

	// 4. Dengan cookie -> diteruskan ke upstream.
	code, _, body = do("GET", "/rahasia", nil, cookie)
	if code != 200 || body != "UPSTREAM OK" {
		t.Fatalf("GET dengan cookie: status=%d body=%q", code, body)
	}

	// 5. Cookie hasil comotan untuk site lain tidak dibuat di sini, tapi
	// cookie rusak harus tetap digerbang.
	code, _, _ = do("GET", "/rahasia", nil, AuthCookieName+"=12345.rusak")
	if code != http.StatusUnauthorized {
		t.Fatalf("cookie rusak: status=%d, mau 401", code)
	}
}

func TestAuthChallengeNonaktif(t *testing.T) {
	e := newTestEnv(t, nil)
	e.addSite("bebas.test", map[string]any{})
	req, err := http.NewRequest("GET", e.proxyURL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "bebas.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("site tanpa gerbang: status=%d, mau 200", resp.StatusCode)
	}
	// AuthPath pada site tanpa gerbang -> 302 ke beranda.
	client := noRedirectClient()
	req2, _ := http.NewRequest("GET", e.proxyURL+AuthPath, nil)
	req2.Host = "bebas.test"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound ||
		resp2.Header.Get("Location") != "/" {
		t.Fatalf("AuthPath nonaktif: status=%d location=%q",
			resp2.StatusCode, resp2.Header.Get("Location"))
	}
}
