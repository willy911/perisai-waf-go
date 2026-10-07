// Command setpassword mengatur username + password login dashboard.
//
// perisai-setpassword --config config.yaml
//
// Password tidak disimpan plaintext — yang ditulis ke config.yaml hanyalah
// hash PBKDF2. Token API lama (dashboard.token) tetap berlaku untuk skrip.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/willy911/perisai-waf/internal/auth"
	"github.com/willy911/perisai-waf/internal/config"
)

func promptReader(prompt string) string {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	pw, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(pw))
}

func main() {
	configPath := flag.String("config", "config.yaml", "path file konfigurasi YAML")
	flag.Parse()

	if _, err := os.Stat(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "config tidak ditemukan: %s\n", *configPath)
		os.Exit(1)
	}

	username := promptReader("Username [admin]: ")
	if username == "" {
		username = "admin"
	}
	pw1 := promptPassword("Password: ")
	if len(pw1) < 8 {
		fmt.Fprintln(os.Stderr, "Password minimal 8 karakter.")
		os.Exit(1)
	}
	pw2 := promptPassword("Ulangi password: ")
	if pw1 != pw2 {
		fmt.Fprintln(os.Stderr, "Password tidak sama.")
		os.Exit(1)
	}

	hash, err := auth.HashPassword(pw1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gagal hash password: %v\n", err)
		os.Exit(1)
	}
	if err := config.SaveDashboardAuth(*configPath, username, hash); err != nil {
		fmt.Fprintf(os.Stderr, "gagal menyimpan: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Login dashboard '%s' tersimpan di %s.\n", username, *configPath)
	fmt.Println("Catatan: session login hangus saat WAF di-restart.")
}
