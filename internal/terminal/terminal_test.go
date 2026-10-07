package terminal

import (
	"strings"
	"testing"
	"time"
)

func TestStartEcho(t *testing.T) {
	s, err := Start(Config{Enabled: true, Shell: "sh", WorkDir: t.TempDir()}, "test")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()
	s.Resize(80, 24)

	if _, err := s.Write([]byte("echo hello-terminal-123\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var sb strings.Builder
	buf := make([]byte, 4096)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout menunggu output, dapat: %q", sb.String())
		default:
		}
		n, err := s.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), "hello-terminal-123") {
				break
			}
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
}

func TestResolveWorkDir(t *testing.T) {
	if got := ResolveWorkDir(Config{WorkDir: "/app"}); got != "/app" {
		t.Fatalf("got %q", got)
	}
	if got := ResolveWorkDir(Config{}); got == "" {
		t.Fatal("workdir kosong tidak boleh")
	}
}

func TestResolveShellFallback(t *testing.T) {
	got := ResolveShell(Config{Shell: "shell-yang-tidak-ada-xyz"})
	if got != "bash" && got != "sh" {
		t.Fatalf("fallback tak valid: %q", got)
	}
}

func TestSessionClose(t *testing.T) {
	s, err := Start(Config{Enabled: true, Shell: "sh"}, "test")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Close()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done tidak tertutup setelah Close")
	}
}
