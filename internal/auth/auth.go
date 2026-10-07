// Package auth: hash password PBKDF2-SHA256 dan session token in-memory.
// Format hash: pbkdf2_sha256$<iterasi>$<salt_hex>$<hash_hex> (kompatibel
// dengan perisai/auth.py versi Python).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	hashIterations = 200_000
	saltBytes      = 16
	sessionTTL     = 12 * time.Hour
)

// HashPassword membuat hash untuk password baru.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2.Key([]byte(password), salt, hashIterations, 32, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		hashIterations, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// CheckPassword memverifikasi password terhadap hash tersimpan.
func CheckPassword(password, hashed string) bool {
	parts := strings.Split(hashed, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	dk := pbkdf2.Key([]byte(password), salt, iters, len(want), sha256.New)
	return subtle.ConstantTimeCompare(dk, want) == 1
}

type session struct {
	username  string
	expiresAt time.Time
}

// SessionStore menyimpan token sesi login (in-memory, 12 jam).
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]session{}}
}

// Create membuat token sesi baru untuk username.
func (s *SessionStore) Create(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = session{username: username, expiresAt: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	return tok, nil
}

// Validate memeriksa token masih berlaku.
func (s *SessionStore) Validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.sessions[token]
	if !ok || time.Now().After(se.expiresAt) {
		delete(s.sessions, token)
		return false
	}
	return true
}

// Invalidate menghapus satu token (logout).
func (s *SessionStore) Invalidate(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// LoginThrottle: anti brute-force — 5x gagal = kunci 5 menit per IP.
type LoginThrottle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func NewLoginThrottle() *LoginThrottle {
	return &LoginThrottle{failures: map[string][]time.Time{}}
}

const (
	maxFailures   = 5
	lockDuration  = 5 * time.Minute
	failWindow    = 10 * time.Minute
)

// Locked melaporkan apakah IP sedang dikunci.
func (t *LoginThrottle) Locked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cut := time.Now().Add(-failWindow)
	fs := t.failures[ip][:0]
	for _, f := range t.failures[ip] {
		if f.After(cut) {
			fs = append(fs, f)
		}
	}
	t.failures[ip] = fs
	if len(fs) >= maxFailures && time.Since(fs[len(fs)-1]) < lockDuration {
		return true
	}
	return false
}

// RegisterFailure mencatat satu kegagalan login.
func (t *LoginThrottle) RegisterFailure(ip string) {
	t.mu.Lock()
	t.failures[ip] = append(t.failures[ip], time.Now())
	t.mu.Unlock()
}

// RegisterSuccess menghapus catatan kegagalan IP.
func (t *LoginThrottle) RegisterSuccess(ip string) {
	t.mu.Lock()
	delete(t.failures, ip)
	t.mu.Unlock()
}
