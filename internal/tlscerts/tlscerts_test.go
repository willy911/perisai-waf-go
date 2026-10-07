// Test tlscerts: port dari tests/test_tlscerts.py (Python).
package tlscerts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSigned membuat pasangan cert+key PEM self-signed (menggantikan
// openssl req -x509 di test Python).
func selfSigned(t *testing.T, cn string, san []string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		DNSNames:     san,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var cb, kb strings.Builder
	if err := pem.Encode(&cb, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&kb, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	return cb.String(), kb.String()
}

func TestParseExpiry(t *testing.T) {
	certPEM, _ := selfSigned(t, "contoh.test", []string{"contoh.test"})
	exp, err := ParseExpiry(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// cert dibuat 48 jam ke depan
	if d := time.Until(exp); d < 47*time.Hour || d > 48*time.Hour {
		t.Fatalf("expiry tak masuk akal: %v", exp)
	}
}

func TestParseExpiryBukanPEM(t *testing.T) {
	if _, err := ParseExpiry("bukan-sertifikat"); err == nil {
		t.Fatal("harusnya error untuk input bukan PEM")
	}
}

func TestDomains(t *testing.T) {
	certPEM, _ := selfSigned(t, "contoh.test",
		[]string{"contoh.test", "www.contoh.test"})
	doms, err := Domains(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"contoh.test", "www.contoh.test"} {
		found := false
		for _, d := range doms {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("domain %q tidak ditemukan di %v", want, doms)
		}
	}
}

func TestDomainsCNBelumDiSAN(t *testing.T) {
	// CN ditambahkan bila belum ada di SAN (seperti versi Python)
	certPEM, _ := selfSigned(t, "cn.test", []string{"san.test"})
	doms, err := Domains(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cn.test", "san.test"} {
		found := false
		for _, d := range doms {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("domain %q tidak ditemukan di %v", want, doms)
		}
	}
}

func TestValidatePairOK(t *testing.T) {
	certPEM, keyPEM := selfSigned(t, "contoh.test", []string{"contoh.test"})
	if err := ValidatePair(certPEM, keyPEM); err != nil {
		t.Fatalf("pasangan cocok harusnya valid: %v", err)
	}
}

func TestValidatePairMismatch(t *testing.T) {
	// vektor dari test Python: cert A + key B -> ValueError
	certA, _ := selfSigned(t, "a.test", []string{"a.test"})
	_, keyB := selfSigned(t, "b.test", []string{"b.test"})
	if err := ValidatePair(certA, keyB); err == nil {
		t.Fatal("harusnya error untuk pasangan yang tidak cocok")
	}
}

func TestValidatePairBukanPEM(t *testing.T) {
	// vektor dari test Python: input bukan PEM -> ValueError
	if err := ValidatePair("bukan-sertifikat", "bukan-key"); err == nil {
		t.Fatal("harusnya error untuk input bukan PEM")
	}
}

func TestValidatePairKeyRusak(t *testing.T) {
	certPEM, _ := selfSigned(t, "contoh.test", []string{"contoh.test"})
	if err := ValidatePair(certPEM, "-----BEGIN PRIVATE KEY-----\nrusak\n-----END PRIVATE KEY-----\n"); err == nil {
		t.Fatal("harusnya error untuk key rusak")
	}
}
