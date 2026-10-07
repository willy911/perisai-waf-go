// Package terminal: sesi shell interaktif via websocket untuk menu Terminal
// di dashboard. Shell dijalankan dengan PTY dan direktori kerja dikunci ke
// folder kerja aplikasi (di Docker: /app, yaitu folder perisai-waf).
package terminal

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"
)

// Config diisi dari config.TerminalConfig.
type Config struct {
	Enabled bool
	Shell   string
	WorkDir string
}

// ResolveWorkDir mengembalikan direktori kerja absolut untuk sesi terminal.
// Bila tidak dikonfigurasi, dipakai direktori kerja proses saat start
// (di Docker itu /app = folder perisai-waf).
func ResolveWorkDir(cfg Config) string {
	if cfg.WorkDir != "" {
		return cfg.WorkDir
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// ResolveShell memilih shell: yang dikonfigurasi bila ada di PATH,
// fallback ke "sh".
func ResolveShell(cfg Config) string {
	if cfg.Shell != "" {
		if _, err := exec.LookPath(cfg.Shell); err == nil {
			return cfg.Shell
		}
	}
	if _, err := exec.LookPath("bash"); err == nil {
		return "bash"
	}
	return "sh"
}

// Session adalah satu sesi shell dengan PTY.
type Session struct {
	cmd  *exec.Cmd
	pty  *os.File
	once sync.Once
	done chan struct{}
}

// Start membuka shell baru di workDir. remote adalah identitas klien
// (IP) untuk keperluan audit log.
func Start(cfg Config, remote string) (*Session, error) {
	shell := ResolveShell(cfg)
	workDir := ResolveWorkDir(cfg)

	cmd := exec.Command(shell, "--login")
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"PERISAI_TERMINAL=1",
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka PTY: %w", err)
	}
	s := &Session{cmd: cmd, pty: ptmx, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		s.once.Do(func() { close(s.done) })
	}()
	log.Printf("[terminal] sesi dibuka dari %s (shell=%s, cwd=%s)", remote, shell, workDir)
	return s, nil
}

// Write mengirim input pengguna ke shell. Setiap baris yang diakhiri Enter
// dicatat ke audit log (tanpa echo password — shell interaktif biasa).
func (s *Session) Write(p []byte) (int, error) {
	auditInput(p)
	return s.pty.Write(p)
}

// Read membaca output dari shell.
func (s *Session) Read(p []byte) (int, error) {
	return s.pty.Read(p)
}

// Resize mengubah ukuran PTY.
func (s *Session) Resize(cols, rows int) {
	if cols < 1 {
		cols = 80
	}
	if rows < 1 {
		rows = 24
	}
	_ = pty.Setsize(s.pty, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Done channel yang ditutup saat shell keluar.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close menutup sesi dan mematikan shell.
func (s *Session) Close() {
	s.once.Do(func() { close(s.done) })
	_ = s.pty.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

// auditInput mencatat baris perintah lengkap ke log untuk audit.
// Hanya baris yang diakhiri Enter (\r) yang dicatat.
func auditInput(p []byte) {
	text := string(p)
	for _, line := range strings.Split(text, "\r") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(trimmed, "\x1b") {
			continue // lewati escape sequence / input parsial
		}
		log.Printf("[terminal] $ %s", trimmed)
	}
}
