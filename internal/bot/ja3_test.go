package bot

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

// buildClientHello merakit satu record TLS ClientHello dari parameter,
// untuk menguji parser tanpa fixture biner.
func buildClientHello(t *testing.T, version uint16, ciphers []uint16,
	exts []struct {
		typ  uint16
		data []byte
	},
) []byte {
	t.Helper()
	hello := []byte{byte(version >> 8), byte(version)}
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0x00)                // session_id kosong
	hello = append(hello, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		hello = append(hello, byte(c>>8), byte(c))
	}
	hello = append(hello, 0x01, 0x00) // compression: 1 metode (null)
	var ebody []byte
	for _, e := range exts {
		ebody = append(ebody, byte(e.typ>>8), byte(e.typ),
			byte(len(e.data)>>8), byte(len(e.data)))
		ebody = append(ebody, e.data...)
	}
	hello = append(hello, byte(len(ebody)>>8), byte(len(ebody)))
	hello = append(hello, ebody...)

	hs := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	hs = append(hs, hello...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func TestParseClientHello(t *testing.T) {
	rec := buildClientHello(t, 0x0303,
		[]uint16{0x1301, 0x1302, 0x0a0a}, // 0x0a0a = GREASE, harus diabaikan
		[]struct {
			typ  uint16
			data []byte
		}{
			{0, []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}}, // SNI
			{10, []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17}}, // groups: 29, 23
			{11, []byte{0x01, 0x00}},                        // point formats: 0
			{0x1a1a, []byte{0x00}},                          // GREASE ext, abaikan
		})
	info := parseClientHello(rec)
	want := "771,4865-4866,0-10-11,29-23,0"
	if info.JA3 != want {
		t.Fatalf("JA3 = %q, want %q", info.JA3, want)
	}
	sum := md5.Sum([]byte(want))
	if info.Hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash = %q, want md5(%q)", info.Hash, want)
	}
}

func TestParseClientHelloBukanTLS(t *testing.T) {
	// "GET / HTTP/1.1" nyasar ke port TLS: harus JA3 kosong, tanpa error.
	info := parseClientHello([]byte("GET / HTTP/1.1\r\n"))
	if info.JA3 != "" || info.Hash != "" {
		t.Fatalf("mestinya kosong, dapat %+v", info)
	}
	// record terpotong
	info = parseClientHello([]byte{0x16, 0x03, 0x01, 0x00})
	if info.JA3 != "" {
		t.Fatalf("record terpotong mestinya kosong, dapat %+v", info)
	}
}

func TestPeekJA3Replay(t *testing.T) {
	// PeekJA3 harus mengembalikan koneksi yang me-replay bytes utuh.
	rec := buildClientHello(t, 0x0303, []uint16{0x1301}, nil)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c2.Write(rec)
	}()
	info, replayed, err := PeekJA3(c1)
	if err != nil {
		t.Fatal(err)
	}
	if info.Hash == "" {
		t.Fatal("JA3 kosong untuk ClientHello valid")
	}
	got := make([]byte, len(rec))
	if _, err := io.ReadFull(replayed, got); err != nil {
		t.Fatal(err)
	}
	for i := range rec {
		if got[i] != rec[i] {
			t.Fatalf("replay rusak di byte %d", i)
		}
	}
}
