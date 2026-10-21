package proxy

// Test halaman blokir kustom: template dari setting block_page_html
// dipakai untuk respons 403 dengan placeholder terisi & ter-escape;
// tanpa setting, halaman bawaan yang dipakai.

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBlockPageKustom(t *testing.T) {
	e := newTestEnv(t, nil)
	if err := e.store.SetSetting("block_page_html",
		"BLOK|{{IP}}|{{RULE}}|{{PATH}}|{{REQUEST_ID}}"); err != nil {
		t.Fatal(err)
	}
	xss := "/serang?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
	resp, err := http.Get(e.proxyURL + xss)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status=%d, mau 403", resp.StatusCode)
	}
	got := string(body)
	if !strings.HasPrefix(got, "BLOK|127.0.0.1|") {
		t.Fatalf("placeholder IP tidak terisi: %q", got)
	}
	if !strings.Contains(got, "|/serang|") {
		t.Fatalf("placeholder PATH tidak terisi: %q", got)
	}
	if strings.Contains(got, "{{") {
		t.Fatalf("masih ada placeholder mentah: %q", got)
	}
	row := e.lastRequest()
	rule, _ := row["top_rule"].(string)
	if rule == "" || !strings.Contains(got, "|"+rule+"|") {
		t.Fatalf("placeholder RULE tidak cocok dengan log (%q): %q", rule, got)
	}
}

func TestBlockPageBawaanTetap(t *testing.T) {
	e := newTestEnv(t, nil)
	xss := "/cari?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
	resp, err := http.Get(e.proxyURL + xss)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 ||
		!strings.Contains(string(body), "Akses Ditolak") {
		t.Fatalf("tanpa setting harusnya halaman bawaan: status=%d body=%q",
			resp.StatusCode, body)
	}
}

func TestBlockPageCacheTTL(t *testing.T) {
	e := newTestEnv(t, nil)
	if err := e.store.SetSetting("block_page_html", "V1"); err != nil {
		t.Fatal(err)
	}
	if got := e.srv.customBlockPageHTML(); got != "V1" {
		t.Fatalf("bacaan pertama = %q, mau V1", got)
	}
	// Ubah setting langsung: dalam TTL cache, nilai lama tetap dipakai.
	if err := e.store.SetSetting("block_page_html", "V2"); err != nil {
		t.Fatal(err)
	}
	if got := e.srv.customBlockPageHTML(); got != "V1" {
		t.Fatalf("cache TTL tidak bekerja: dapat %q, mau V1", got)
	}
}
