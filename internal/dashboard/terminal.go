package dashboard

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/willy911/perisai-waf/internal/terminal"
)

// wsUpgrader untuk endpoint terminal. CheckOrigin dilonggarkan karena
// dashboard bisa diakses via IP/domain berbeda — endpoint tetap wajib
// terautentikasi (token sesi), jadi aman dari CSRF lintas situs.
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Protokol pesan websocket terminal (JSON):
//   klien -> server: {"t":"in","d":"teks"} | {"t":"resize","cols":N,"rows":N}
//   server -> klien: {"t":"out","d":"teks"}
type wsMsg struct {
	T    string `json:"t"`
	D    string `json:"d,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleTerminalConfig mengembalikan status fitur terminal untuk UI.
func (d *Dashboard) handleTerminalConfig(w http.ResponseWriter, r *http.Request) {
	cfg := d.cfg.Terminal
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  cfg.Enabled,
		"shell":    terminal.ResolveShell(terminal.Config{Shell: cfg.Shell}),
		"work_dir": terminal.ResolveWorkDir(terminal.Config{WorkDir: cfg.WorkDir}),
	})
}

// handleTerminalWS: websocket shell interaktif. Wajib login (token sesi di
// ?token=). Shell berjalan di folder kerja aplikasi (di Docker: /app).
func (d *Dashboard) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	if !d.cfg.Terminal.Enabled {
		http.Error(w, "terminal dimatikan (terminal.enabled=false)", http.StatusForbidden)
		return
	}
	if !d.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[terminal] upgrade gagal: %v", err)
		return
	}
	defer conn.Close()

	sess, err := terminal.Start(terminal.Config{
		Enabled: true,
		Shell:   d.cfg.Terminal.Shell,
		WorkDir: d.cfg.Terminal.WorkDir,
	}, clientIPFromRequest(r))
	if err != nil {
		_ = conn.WriteJSON(wsMsg{T: "out", D: "\r\nGagal membuka shell: " + err.Error() + "\r\n"})
		return
	}
	defer sess.Close()
	sess.Resize(120, 32)

	var writeMu sync.Mutex
	sendOut := func(text string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteJSON(wsMsg{T: "out", D: text})
	}

	// Pompa output PTY -> websocket.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sess.Read(buf)
			if n > 0 {
				sendOut(string(buf[:n]))
			}
			if err != nil {
				return
			}
		}
	}()

	// Tutup koneksi saat shell keluar.
	go func() {
		<-sess.Done()
		writeMu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shell keluar"),
			time.Now().Add(3*time.Second))
		writeMu.Unlock()
		_ = conn.Close()
	}()

	// Pompa input websocket -> PTY.
	for {
		var m wsMsg
		if err := conn.ReadJSON(&m); err != nil {
			return
		}
		switch m.T {
		case "in":
			if _, err := sess.Write([]byte(m.D)); err != nil {
				return
			}
		case "resize":
			sess.Resize(m.Cols, m.Rows)
		}
	}
}
