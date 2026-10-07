package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/willy911/perisai-waf/internal/auth"
)

// TestTerminalConfigAuth: endpoint config wajib terautentikasi.
func TestTerminalConfigAuth(t *testing.T) {
	hash, _ := auth.HashPassword("rahasia")
	s := newTestSetup(t, hash)

	code, _ := s.do(t, "GET", "/api/terminal/config", nil, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("tanpa token: ingin 401, dapat %d", code)
	}
	code, m := s.doJSON(t, "GET", "/api/terminal/config", nil, "tok-test")
	if code != http.StatusOK {
		t.Fatalf("dengan token: ingin 200, dapat %d", code)
	}
	for _, k := range []string{"enabled", "shell", "work_dir"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("respons kurang kunci %q: %v", k, m)
		}
	}
}

// TestTerminalWS: websocket shell — tolak tanpa token, terima dengan token,
// perintah echo kembali, cwd sesuai konfigurasi.
func TestTerminalWS(t *testing.T) {
	hash, _ := auth.HashPassword("rahasia")
	s := newTestSetup(t, hash)
	s.cfg.Terminal.Enabled = true

	srv := httptest.NewServer(s.d.Handler())
	defer srv.Close()
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Tanpa token -> 401 (bukan upgrade websocket).
	_, resp, err := websocket.DefaultDialer.Dial(wsBase+"/api/terminal/ws", nil)
	if err == nil {
		t.Fatal("dial tanpa token seharusnya gagal")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tanpa token: ingin 401, dapat %d", resp.StatusCode)
	}

	// Dengan token -> sesi shell hidup.
	conn, _, err := websocket.DefaultDialer.Dial(wsBase+"/api/terminal/ws?token=tok-test", nil)
	if err != nil {
		t.Fatalf("dial dengan token: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(wsMsg{T: "in", D: "echo ws-ok-456\n"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var sb strings.Builder
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	for {
		var m wsMsg
		if err := conn.ReadJSON(&m); err != nil {
			t.Fatalf("read: %v (terkumpul: %q)", err, sb.String())
		}
		if m.T == "out" {
			sb.WriteString(m.D)
			if strings.Contains(sb.String(), "ws-ok-456") {
				break
			}
		}
	}

	// Perintah pwd: cwd harus direktori kerja proses (default).
	if err := conn.WriteJSON(wsMsg{T: "in", D: "pwd\n"}); err != nil {
		t.Fatalf("write pwd: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	sb.Reset()
	for {
		var m wsMsg
		if err := conn.ReadJSON(&m); err != nil {
			t.Fatalf("read pwd: %v (terkumpul: %q)", err, sb.String())
		}
		if m.T == "out" {
			sb.WriteString(m.D)
			// output pwd mengandung path cwd; cukup pastikan ada baris path absolut
			if strings.Contains(sb.String(), "/") && strings.Contains(sb.String(), "\n") {
				break
			}
		}
	}
	_ = conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "selesai"))
}

// TestTerminalWSDisabled: bila dimatikan di config, websocket ditolak 403.
func TestTerminalWSDisabled(t *testing.T) {
	hash, _ := auth.HashPassword("rahasia")
	s := newTestSetup(t, hash)
	s.cfg.Terminal.Enabled = false

	srv := httptest.NewServer(s.d.Handler())
	defer srv.Close()
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")

	_, resp, err := websocket.DefaultDialer.Dial(wsBase+"/api/terminal/ws?token=tok-test", nil)
	if err == nil {
		t.Fatal("dial saat terminal dimatikan seharusnya gagal")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ingin 403, dapat %d", resp.StatusCode)
	}
}
