package proxy

// Halaman blokir kustom (fitur SafeLine "custom intercept page"):
// admin dapat mengganti halaman 403 bawaan dengan HTML sendiri lewat
// setting block_page_html. Placeholder {{IP}}, {{RULE}}, {{REQUEST_ID}},
// dan {{PATH}} diganti nilai request (di-escape). Setting dibaca lewat
// cache in-memory TTL 15 detik agar tidak query DB per request.

import (
	"html"
	"strings"
	"time"
)

// blockPageCacheTTL adalah umur cache setting halaman blokir kustom.
const blockPageCacheTTL = 15 * time.Second

// customBlockPageHTML membaca template halaman blokir kustom dari
// settings (dengan cache TTL). "" berarti pakai halaman bawaan.
func (s *Server) customBlockPageHTML() string {
	s.blockMu.Lock()
	defer s.blockMu.Unlock()
	if time.Since(s.blockAt) < blockPageCacheTTL {
		return s.blockCache
	}
	v, _ := s.store.GetSetting("block_page_html", "")
	s.blockCache = v
	s.blockAt = time.Now()
	return v
}

// blockPageFor membangun halaman blokir untuk satu keputusan: template
// kustom bila diatur, selain itu halaman bawaan blockPage().
func (s *Server) blockPageFor(requestID, ip, rule, reqPath, reason string) []byte {
	if tpl := s.customBlockPageHTML(); tpl != "" {
		r := strings.NewReplacer(
			"{{IP}}", html.EscapeString(ip),
			"{{RULE}}", html.EscapeString(rule),
			"{{REQUEST_ID}}", html.EscapeString(requestID),
			"{{PATH}}", html.EscapeString(reqPath),
		)
		return []byte(r.Replace(tpl))
	}
	return blockPage(requestID, reason)
}
