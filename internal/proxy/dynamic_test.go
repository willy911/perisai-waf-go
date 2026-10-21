package proxy

// Test Dynamic Protection: enkripsi dinamis HTML ala SafeLine.
// Roundtrip wrap/unwrap harus persis; lewat proxy, HTML upstream menjadi
// halaman loader (konten asli tidak mentah), JSON & mode nonaktif utuh.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestDynamicWrapRoundtrip(t *testing.T) {
	htmlBody := []byte("<html><head><title>Halo Dunia</title></head>" +
		"<body><h1>Selamat datang — éè</h1><script>var x=1;</script></body></html>")
	page := dynamicWrap(htmlBody)
	if bytes.Contains(page, []byte("Halo Dunia")) ||
		bytes.Contains(page, htmlBody) {
		t.Fatal("konten asli muncul mentah di halaman loader")
	}
	if !bytes.Contains(page, []byte("document.write")) {
		t.Fatal("halaman loader tidak memuat script decoder")
	}
	back, ok := dynamicUnwrap(page)
	if !ok {
		t.Fatal("dynamicUnwrap gagal mengekstrak kunci/data")
	}
	if !bytes.Equal(back, htmlBody) {
		t.Fatalf("roundtrip tidak persis:\n%q\n%q", back, htmlBody)
	}
	// Kunci acak per respons -> dua bungkus tidak identik.
	if bytes.Equal(page, dynamicWrap(htmlBody)) {
		t.Fatal("dua dynamicWrap identik — kunci tidak acak")
	}
}

func TestDynamicShouldWrap(t *testing.T) {
	mk := func(status int, ct, enc string) *http.Response {
		h := http.Header{}
		if ct != "" {
			h.Set("Content-Type", ct)
		}
		if enc != "" {
			h.Set("Content-Encoding", enc)
		}
		return &http.Response{StatusCode: status, Header: h}
	}
	htmlBody := []byte("<HTML><body>x</body></HTML>")
	if !dynamicShouldWrap(mk(200, "text/html; charset=utf-8", ""), htmlBody) {
		t.Fatal("HTML 200 harus dibungkus")
	}
	if dynamicShouldWrap(mk(200, "application/json", ""), []byte(`{"a":1}`)) {
		t.Fatal("JSON tidak boleh dibungkus")
	}
	if dynamicShouldWrap(mk(404, "text/html", ""), htmlBody) {
		t.Fatal("non-200 tidak boleh dibungkus")
	}
	if dynamicShouldWrap(mk(200, "text/html", "gzip"), htmlBody) {
		t.Fatal("respons ter-encoding tidak boleh dibungkus")
	}
	if dynamicShouldWrap(mk(200, "text/html", ""), []byte("teks biasa")) {
		t.Fatal("body tanpa <html tidak boleh dibungkus")
	}
}

func TestDynamicProtectionProxy(t *testing.T) {
	e := newTestEnv(t, nil)
	const htmlAsli = "<html><head><title>Rahasia</title></head>" +
		"<body>Halo Dunia</body></html>"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(htmlAsli))
	}))
	defer up.Close()
	uu, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(uu.Port())
	e.addSite("dyn.test", map[string]any{
		"dynamic_protection": 1, "upstream_port": port,
	})
	e.addSite("polos.test", map[string]any{"upstream_port": port})

	get := func(host, p string) (int, http.Header, string) {
		req, err := http.NewRequest("GET", e.proxyURL+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// HTML pada site dinamis -> loader; konten asli tidak mentah; bisa
	// didekode kembali persis; Cache-Control no-store.
	code, hdr, body := get("dyn.test", "/")
	if code != 200 {
		t.Fatalf("GET dyn: status=%d", code)
	}
	if strings.Contains(body, "Halo Dunia") || !strings.Contains(body, "var D=") {
		t.Fatalf("respons bukan loader terenkripsi: %q", body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q, mau no-store", hdr.Get("Cache-Control"))
	}
	back, ok := dynamicUnwrap([]byte(body))
	if !ok || string(back) != htmlAsli {
		t.Fatalf("unwrap respons proxy tidak cocok: ok=%v back=%q", ok, back)
	}

	// JSON pada site dinamis -> utuh.
	code, _, body = get("dyn.test", "/api")
	if code != 200 || body != `{"ok":true}` {
		t.Fatalf("JSON berubah: status=%d body=%q", code, body)
	}

	// Site tanpa proteksi -> HTML utuh.
	code, _, body = get("polos.test", "/")
	if code != 200 || body != htmlAsli {
		t.Fatalf("site nonaktif berubah: status=%d body=%q", code, body)
	}
}
