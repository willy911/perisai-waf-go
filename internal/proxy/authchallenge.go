package proxy

// Authentication Challenge per-site (fitur SafeLine): gerbang password
// sederhana di depan aplikasi. Pengunjung tanpa cookie bukti-login yang
// valid hanya menerima halaman form; setelah password benar, server
// menerbitkan cookie bertanda tangan HMAC (pola sama seperti token
// challenge: "expiry.hmac") yang berlaku 24 jam.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/willy911/perisai-waf/internal/auth"
	"github.com/willy911/perisai-waf/internal/config"
)

// authSig menghitung HMAC-SHA256(secret, "auth.<siteID>.<expiry>") hex.
func authSig(secret, siteID string, expiry int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "auth.%s.%d", siteID, expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

// issueAuthToken membuat token cookie auth "expiry.hexhmac" untuk site.
func issueAuthToken(secret, siteID string) string {
	expiry := time.Now().Unix() + AuthTTL
	return fmt.Sprintf("%d.%s", expiry, authSig(secret, siteID, expiry))
}

// verifyAuthToken memvalidasi token cookie auth untuk site.
func verifyAuthToken(secret, siteID, token string) bool {
	if token == "" {
		return false
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if expiry < time.Now().Unix() {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(authSig(secret, siteID, expiry)))
}

// authCookie mengambil nilai cookie auth dari request.
func authCookie(r *http.Request) string {
	for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
		k, v, found := strings.Cut(part, "=")
		if found && strings.TrimSpace(k) == AuthCookieName {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// sanitizeNext membersihkan target redirect setelah login: hanya path
// lokal absolut yang diterima (cegah open redirect).
func sanitizeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") ||
		strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// authPage adalah halaman form gerbang password (memakai kerangka
// htmlPage). next di-escape; pesan error ditampilkan bila ada.
func authPage(next, errMsg string) []byte {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="desc" style="color:#f87171;margin-top:12px">` +
			html.EscapeString(errMsg) + `</div>`
	}
	extra := `<form method="POST" action="` + AuthPath + `">` +
		`<input type="hidden" name="next" value="` +
		html.EscapeString(next) + `">` +
		`<div style="margin-top:18px"><input type="password" name="password"` +
		` placeholder="Password" autocomplete="current-password" autofocus` +
		` style="width:100%;box-sizing:border-box;padding:10px 12px;` +
		`border-radius:8px;border:1px solid #334155;background:#0f172a;` +
		`color:#e2e8f0"></div>` +
		`<button type="submit" style="margin-top:14px;width:100%;` +
		`background:#6366f1;color:#fff;border:0;padding:10px 24px;` +
		`border-radius:8px;font-weight:600;cursor:pointer">Masuk</button>` +
		`</form>` + errHTML
	return htmlPage("Kawasan Terbatas 🔐",
		"Website ini dilindungi password tambahan. "+
			"Masukkan password untuk melanjutkan.",
		"auth-challenge", extra)
}

// authAktif melaporkan apakah gerbang password berlaku untuk site ini.
func authAktif(site *config.Site) bool {
	return site != nil && site.AuthChallengeEnabled &&
		site.AuthChallengeHash != ""
}

// handleAuth melayani endpoint AuthPath: GET menampilkan form login,
// POST memverifikasi password (internal/auth.CheckPassword). Sukses ->
// Set-Cookie perisai_auth + 302 ke next; gagal -> form lagi (401).
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request,
	body []byte) {
	site := s.route(hostOnly(r.Host))
	if !authAktif(site) {
		// Gerbang tidak aktif untuk host ini -> kembali ke beranda.
		w.Header().Set("Location", "/")
		s.writeDirect(w, http.StatusFound,
			[]byte(`<html><body><a href="/">lanjutkan</a></body></html>`),
			"text/html; charset=utf-8", nil)
		return
	}
	if r.Method != http.MethodPost {
		next := sanitizeNext(r.URL.Query().Get("next"))
		s.writeDirect(w, http.StatusUnauthorized, authPage(next, ""),
			"text/html; charset=utf-8", nil)
		return
	}
	vals, _ := url.ParseQuery(string(body))
	next := sanitizeNext(vals.Get("next"))
	if !auth.CheckPassword(vals.Get("password"), site.AuthChallengeHash) {
		s.writeDirect(w, http.StatusUnauthorized,
			authPage(next, "Password salah. Coba lagi."),
			"text/html; charset=utf-8", nil)
		return
	}
	token := issueAuthToken(s.secret, site.ID)
	http.SetCookie(w, &http.Cookie{
		Name: AuthCookieName, Value: token, Path: "/",
		MaxAge: AuthTTL, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Location", next)
	s.writeDirect(w, http.StatusFound,
		[]byte(`<html><body>Login berhasil… <a href="`+
			html.EscapeString(next)+`">lanjutkan</a></body></html>`),
		"text/html; charset=utf-8", nil)
}
