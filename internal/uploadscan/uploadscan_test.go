package uploadscan

import (
	"strings"
	"testing"

	"github.com/willy911/perisai-waf/internal/config"
)

func cfg() config.UploadScanConfig {
	return config.UploadScanConfig{
		Enabled:           true,
		MaxFileMB:         10,
		BlockedExtensions: DefaultBlockedExtensions,
	}
}

func jpeg() []byte {
	// header JPEG minimal + isi polos
	b := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	b = append(b, []byte("foto biasa tanpa kode jahat")...)
	return b
}

// Ekstensi .php langsung diblokir.
func TestEkstensiPHPDiblokir(t *testing.T) {
	if ok, reason := Scan("shell.php", []byte("<?php echo 1;"), cfg()); !ok {
		t.Fatal("shell.php harusnya diblokir")
	} else if !strings.Contains(reason, "ekstensi diblokir") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// Double extension: shell.php.jpg diblokir.
func TestDoubleExtensionDiblokir(t *testing.T) {
	if ok, reason := Scan("shell.php.jpg", jpeg(), cfg()); !ok {
		t.Fatal("shell.php.jpg harusnya diblokir")
	} else if !strings.Contains(reason, "double extension") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// String EICAR diblokir.
func TestEICARDiblokir(t *testing.T) {
	content := append([]byte("header\n"), EICAR...)
	if ok, reason := Scan("test.txt", content, cfg()); !ok {
		t.Fatal("EICAR harusnya diblokir")
	} else if !strings.Contains(reason, "EICAR") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// Webshell: $_POST[...](...) diblokir (pola "webshell via $_GET/$_POST").
// Isi sengaja tanpa tag <?php agar tidak kena cek PHP-disguised dulu.
func TestWebshellEvalPostDiblokir(t *testing.T) {
	content := []byte(`$x = $_POST['a']($_POST['b']);`)
	if ok, reason := Scan("cmd.txt", content, cfg()); !ok {
		t.Fatal("webshell $_POST[...]( harusnya diblokir")
	} else if !strings.Contains(reason, "pola webshell") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// Tag PHP + fungsi eksekusi di tengah file diblokir (pola 7).
func TestTagPHPEvalDiblokir(t *testing.T) {
	content := []byte(`<html><body><?php eval($_POST['x']); ?></body></html>`)
	if ok, reason := Scan("page.html", content, cfg()); !ok {
		t.Fatal("tag PHP + eval harusnya diblokir")
	} else if !strings.Contains(reason, "pola webshell") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// eval(base64_decode(...)) diblokir.
func TestEvalBase64Diblokir(t *testing.T) {
	content := []byte(`x = eval(base64_decode("e30="))`)
	if ok, reason := Scan("a.txt", content, cfg()); !ok {
		t.Fatal("eval(base64_decode harusnya diblokir")
	} else if !strings.Contains(reason, "eval(base64_decode)") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// Fungsi eksekusi shell diblokir.
func TestShellExecDiblokir(t *testing.T) {
	if ok, _ := Scan("a.txt", []byte(`<?php shell_exec($_GET['c']); ?>`), cfg()); !ok {
		t.Fatal("shell_exec harusnya diblokir")
	}
}

// File JPG biasa lolos.
func TestJpgBiasaLolos(t *testing.T) {
	if ok, reason := Scan("foto.jpg", jpeg(), cfg()); ok {
		t.Fatalf("foto.jpg biasa harusnya lolos, malah: %q", reason)
	}
}

// Null byte di nama file diblokir.
func TestNullByteDiblokir(t *testing.T) {
	if ok, _ := Scan("a.php\x00.jpg", jpeg(), cfg()); !ok {
		t.Fatal("null byte harusnya diblokir")
	}
}

// Magic bytes MZ (executable Windows) diblokir.
func TestMagicMZDiblokir(t *testing.T) {
	if ok, reason := Scan("prog.jpg", []byte("MZ\x90\x00payload"), cfg()); !ok {
		t.Fatal("MZ harusnya diblokir")
	} else if !strings.Contains(reason, "executable") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// Magic bytes ELF diblokir.
func TestMagicELFDiblokir(t *testing.T) {
	if ok, _ := Scan("bin.jpg", []byte{0x7f, 'E', 'L', 'F', 0x02}, cfg()); !ok {
		t.Fatal("ELF harusnya diblokir")
	}
}

// Kode PHP disamarkan sebagai file lain diblokir.
func TestPHPTersamarDiblokir(t *testing.T) {
	content := []byte("<?php echo 'hello'; ?>")
	if ok, reason := Scan("foto.jpg", content, cfg()); !ok {
		t.Fatal("PHP tersamar harusnya diblokir")
	} else if !strings.Contains(reason, "disamarkan") {
		t.Fatalf("alasan salah: %q", reason)
	}
}

// File kosong lolos (tak ada yang dipindai).
func TestFileKosongLolos(t *testing.T) {
	if ok, _ := Scan("x.txt", nil, cfg()); ok {
		t.Fatal("file kosong harusnya lolos")
	}
}

// Case-insensitive: .PHP juga diblokir.
func TestEkstensiKapitalDiblokir(t *testing.T) {
	if ok, _ := Scan("shell.PHP", []byte("x"), cfg()); !ok {
		t.Fatal("shell.PHP harusnya diblokir")
	}
}
