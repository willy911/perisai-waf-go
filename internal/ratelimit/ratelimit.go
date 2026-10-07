// Package ratelimit menerapkan rate limiter token-bucket per key.
// Merupakan port dari perisai/ratelimit.py (Python).
package ratelimit

import (
	"sync"
	"time"
)

// bucket menyimpan state token bucket untuk satu key.
type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter adalah rate limiter token-bucket per key, aman dipakai
// dari banyak goroutine sekaligus.
type Limiter struct {
	rps    float64
	burst  int
	mu     sync.Mutex
	bucket map[string]*bucket
}

// New membuat Limiter baru: rps token terisi ulang per detik,
// burst jumlah token maksimum (kapasitas bucket).
func New(rps float64, burst int) *Limiter {
	return &Limiter{
		rps:    rps,
		burst:  burst,
		bucket: make(map[string]*bucket),
	}
}

// Allow mengembalikan true bila request dengan key boleh lewat
// (mengambil satu token), false bila bucket kosong.
// Sama persis seperti RateLimiter.allow di Python: token terisi
// ulang berdasarkan selisih waktu monotonik, dibatasi burst.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.bucket[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst), last: now}
		l.bucket[key] = b
	}
	tokens := b.tokens + now.Sub(b.last).Seconds()*l.rps
	if tokens > float64(l.burst) {
		tokens = float64(l.burst)
	}
	if tokens >= 1.0 {
		b.tokens = tokens - 1.0
		b.last = now
		return true
	}
	b.tokens = tokens
	b.last = now
	return false
}

// Reset menghapus state bucket untuk key (berguna untuk pengujian
// atau saat konfigurasi rate limit berubah).
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.bucket, key)
}
