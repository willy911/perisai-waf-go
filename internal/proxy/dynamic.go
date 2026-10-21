package proxy

// Dynamic Protection (fitur SafeLine): enkripsi dinamis halaman HTML.
// Body HTML upstream di-XOR dengan kunci acak 16 byte per respons lalu
// di-base64; yang sampai ke browser hanya halaman loader kecil berisi
// script decoder (atob -> XOR per potongan 32KB -> TextDecoder UTF-8 ->
// document.write). Konten asli tidak pernah muncul mentah di respons,
// sehingga scraper/peniru halaman tidak bisa membacanya langsung.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"mime"
	"net/http"
	"strings"
)

// dynamicMaxBody adalah batas ukuran body HTML yang ditransformasi (2MB).
const dynamicMaxBody = 2 << 20

// dynamicShouldWrap memutuskan apakah respons layak dibungkus loader:
// status 200, Content-Type text/html, tanpa Content-Encoding (identity),
// body mengandung "<html", dan ukuran <= dynamicMaxBody.
func dynamicShouldWrap(resp *http.Response, body []byte) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err == nil {
		if mt != "text/html" {
			return false
		}
	} else if !strings.Contains(strings.ToLower(ct), "text/html") {
		return false
	}
	if len(body) == 0 || len(body) > dynamicMaxBody {
		return false
	}
	return bytes.Contains(bytes.ToLower(body), []byte("<html"))
}

// dynamicWrap membungkus body HTML ke halaman loader terenkripsi.
func dynamicWrap(body []byte) []byte {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return body // gagal membuat kunci -> kirim apa adanya
	}
	enc := make([]byte, len(body))
	for i, b := range body {
		enc[i] = b ^ key[i%len(key)]
	}
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">`)
	sb.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	sb.WriteString(`<title>Memuat…</title></head><body>`)
	sb.WriteString(`<noscript>Aktifkan JavaScript untuk melihat halaman ini.</noscript>`)
	sb.WriteString(`<script>(function(){`)
	sb.WriteString(`var K=atob("` + base64.StdEncoding.EncodeToString(key) + `");`)
	sb.WriteString(`var D="` + base64.StdEncoding.EncodeToString(enc) + `";`)
	sb.WriteString(`var bin=atob(D);var out=new Uint8Array(bin.length);`)
	sb.WriteString(`for(var off=0;off<bin.length;off+=32768){var end=Math.min(off+32768,bin.length);`)
	sb.WriteString(`for(var i=off;i<end;i++){out[i]=bin.charCodeAt(i)^K.charCodeAt(i%K.length);}}`)
	sb.WriteString(`var html=new TextDecoder("utf-8").decode(out);`)
	sb.WriteString(`document.open();document.write(html);document.close();})();</script>`)
	sb.WriteString(`</body></html>`)
	return []byte(sb.String())
}

// dynamicUnwrap adalah pasangan uji dynamicWrap: mengekstrak kunci & data
// dari halaman loader lalu mendekodenya kembali — replikasi persis logika
// decoder JavaScript (atob -> XOR kunci berulang).
func dynamicUnwrap(page []byte) ([]byte, bool) {
	extract := func(marker string) (string, bool) {
		i := bytes.Index(page, []byte(marker))
		if i < 0 {
			return "", false
		}
		rest := page[i+len(marker):]
		j := bytes.IndexByte(rest, '"')
		if j < 0 {
			return "", false
		}
		return string(rest[:j]), true
	}
	kb, ok1 := extract(`var K=atob("`)
	db, ok2 := extract(`var D="`)
	if !ok1 || !ok2 {
		return nil, false
	}
	key, err1 := base64.StdEncoding.DecodeString(kb)
	enc, err2 := base64.StdEncoding.DecodeString(db)
	if err1 != nil || err2 != nil || len(key) == 0 {
		return nil, false
	}
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ key[i%len(key)]
	}
	return out, true
}
