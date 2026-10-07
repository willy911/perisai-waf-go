// Package tlscerts mengelola validasi & introspeksi sertifikat TLS per-site.
// Merupakan port dari perisai/tlscerts.py (Python).
package tlscerts

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

// parseCert mengurai blok CERTIFICATE pertama dari PEM.
func parseCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("format sertifikat tidak valid (bukan PEM)")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sertifikat tidak bisa diparse: %w", err)
	}
	return cert, nil
}

// ParseExpiry mengembalikan waktu kedaluwarsa (notAfter) sertifikat PEM.
func ParseExpiry(certPEM string) (time.Time, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// Domains mengembalikan daftar domain dari CN + SAN sertifikat PEM.
// CN ditambahkan di akhir bila belum ada di SAN (seperti versi Python).
func Domains(certPEM string) ([]string, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	domains := append([]string{}, cert.DNSNames...)
	if cn := cert.Subject.CommonName; cn != "" && !slices.Contains(domains, cn) {
		domains = append(domains, cn)
	}
	return domains, nil
}

// ValidatePair memastikan cert & key PEM cocok satu sama lain.
// Error bila format bukan PEM atau pasangan tidak cocok.
func ValidatePair(certPEM, keyPEM string) error {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("cert/key tidak valid atau tidak cocok: %w", err)
	}
	return nil
}
