// Package bot: pertahanan behavioral terhadap bot — fingerprinting TLS/JA3
// + penilaian perilaku HTTP. Terinspirasi fitur anti-bot SafeLine, ditulis
// ulang dari nol untuk Perisai WAF (pure Go, tanpa dependensi).
package bot

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
)

// JA3Info adalah hasil parsing ClientHello: string JA3 dan hash MD5-nya.
type JA3Info struct {
	JA3  string // "771,4865-4866,...,0" ("" bila bukan/gagal parse TLS)
	Hash string // md5 hex dari JA3 ("" bila JA3 kosong)
}

// grease melaporkan nilai GREASE (RFC 8701) yang harus diabaikan JA3.
func grease(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

// parseClientHello mem-parse satu record TLS ClientHello dan mengembalikan
// info JA3. Mengembalikan JA3Info kosong (tanpa error) bila bytes bukan
// ClientHello yang valid — pemanggil tetap meneruskan koneksi apa adanya.
func parseClientHello(rec []byte) JA3Info {
	var out JA3Info
	if len(rec) < 5 || rec[0] != 0x16 { // bukan TLS handshake
		return out
	}
	reclen := int(rec[3])<<8 | int(rec[4])
	if len(rec) < 5+reclen {
		return out
	}
	body := rec[5 : 5+reclen]
	if len(body) < 4 || body[0] != 0x01 { // bukan client_hello
		return out
	}
	hslen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+hslen {
		return out
	}
	hello := body[4 : 4+hslen]
	if len(hello) < 34 {
		return out
	}
	version := int(hello[0])<<8 | int(hello[1])
	p := hello[34:] // lewati version(2) + random(32)

	// session_id
	if len(p) < 1 {
		return out
	}
	sl := int(p[0])
	p = p[1:]
	if len(p) < sl {
		return out
	}
	p = p[sl:]

	// cipher_suites
	if len(p) < 2 {
		return out
	}
	csl := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csl {
		return out
	}
	var ciphers []string
	for i := 0; i+1 < csl; i += 2 {
		v := int(p[i])<<8 | int(p[i+1])
		if !grease(uint16(v)) {
			ciphers = append(ciphers, fmt.Sprint(v))
		}
	}
	p = p[csl:]

	// compression_methods
	if len(p) < 1 {
		return out
	}
	cl := int(p[0])
	p = p[1:]
	if len(p) < cl {
		return out
	}
	p = p[cl:]

	// extensions
	var exts, curves, formats []string
	if len(p) >= 2 {
		el := int(p[0])<<8 | int(p[1])
		p = p[2:]
		if len(p) >= el {
			ep := p[:el]
			for len(ep) >= 4 {
				et := int(ep[0])<<8 | int(ep[1])
				dl := int(ep[2])<<8 | int(ep[3])
				if len(ep) < 4+dl {
					break
				}
				data := ep[4 : 4+dl]
				if !grease(uint16(et)) {
					exts = append(exts, fmt.Sprint(et))
				}
				switch et {
				case 10: // supported_groups / elliptic_curves
					for i := 0; i+1 < len(data); i += 2 {
						// dua byte pertama adalah panjang list
						if i == 0 {
							continue
						}
						v := int(data[i])<<8 | int(data[i+1])
						if !grease(uint16(v)) {
							curves = append(curves, fmt.Sprint(v))
						}
					}
				case 11: // ec_point_formats
					for i := 1; i < len(data); i++ {
						formats = append(formats, fmt.Sprint(data[i]))
					}
				}
				ep = ep[4+dl:]
			}
		}
	}

	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"))
	sum := md5.Sum([]byte(ja3))
	out.JA3 = ja3
	out.Hash = hex.EncodeToString(sum[:])
	return out
}

// peekConn meneruskan koneksi dengan bytes yang sudah dibaca di awal
// dikembalikan dulu (replay), sehingga tls.Server menerima stream utuh.
type peekConn struct {
	net.Conn
	replay *bytes.Reader
}

func (c *peekConn) Read(b []byte) (int, error) {
	if c.replay.Len() > 0 {
		return c.replay.Read(b)
	}
	return c.Conn.Read(b)
}

// PeekJA3 membaca record TLS pertama dari conn, menghitung JA3, lalu
// mengembalikan koneksi yang me-replay bytes tersebut sehingga handshake
// TLS dapat berjalan normal. Bila bukan TLS / gagal parse, JA3 kosong dan
// koneksi tetap diteruskan apa adanya.
func PeekJA3(conn net.Conn) (JA3Info, net.Conn, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return JA3Info{}, conn, nil // biarkan tls.Server yang menangani
	}
	if hdr[0] != 0x16 {
		// Bukan handshake TLS (mis. HTTP polos nyasar ke port TLS):
		// kembalikan bytes dan lanjutkan tanpa JA3.
		rep := append([]byte{}, hdr[:]...)
		return JA3Info{}, &peekConn{Conn: conn, replay: bytes.NewReader(rep)}, nil
	}
	reclen := int(hdr[3])<<8 | int(hdr[4])
	if reclen <= 0 || reclen > 1<<16 {
		rep := append([]byte{}, hdr[:]...)
		return JA3Info{}, &peekConn{Conn: conn, replay: bytes.NewReader(rep)}, nil
	}
	body := make([]byte, reclen)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep := append(append([]byte{}, hdr[:]...), body...)
		return JA3Info{}, &peekConn{Conn: conn, replay: bytes.NewReader(rep)}, nil
	}
	full := append(append([]byte{}, hdr[:]...), body...)
	info := parseClientHello(full)
	return info, &peekConn{Conn: conn, replay: bytes.NewReader(full)}, nil
}
