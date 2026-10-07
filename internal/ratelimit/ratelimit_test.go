package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// Burst habis lalu request ditolak — perilaku dasar token bucket.
func TestBurstHabis(t *testing.T) {
	l := New(1000, 2)
	if !l.Allow("1.1.1.1") {
		t.Fatal("allow #1 harusnya lolos")
	}
	if !l.Allow("1.1.1.1") {
		t.Fatal("allow #2 harusnya lolos")
	}
	if l.Allow("1.1.1.1") {
		t.Fatal("allow #3 harusnya ditolak (burst habis)")
	}
}

// Key berbeda punya bucket terpisah.
func TestKeyTerpisah(t *testing.T) {
	l := New(1000, 1)
	if !l.Allow("a") {
		t.Fatal("key a harusnya lolos")
	}
	if l.Allow("a") {
		t.Fatal("key a kedua harusnya ditolak")
	}
	if !l.Allow("b") {
		t.Fatal("key b harusnya lolos (bucket terpisah)")
	}
}

// Token terisi ulang seiring waktu.
func TestRefill(t *testing.T) {
	l := New(50, 1) // 1 token per 20ms
	if !l.Allow("k") {
		t.Fatal("harus lolos")
	}
	if l.Allow("k") {
		t.Fatal("harus ditolak (belum refill)")
	}
	time.Sleep(40 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("harus lolos setelah refill")
	}
}

// Refill tidak pernah melebihi burst.
func TestRefillTidakMelebihiBurst(t *testing.T) {
	l := New(100000, 3)
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("allow #%d harus lolos", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("allow #4 harus ditolak (kapasitas = burst)")
	}
}

// Aman dipakai dari banyak goroutine: total lolos tidak boleh
// melebihi burst + refill kecil.
func TestKonkuren(t *testing.T) {
	l := New(10, 20)
	var wg sync.WaitGroup
	var mu sync.Mutex
	lolos := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("k") {
				mu.Lock()
				lolos++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if lolos > 25 { // 20 burst + sedikit refill selama test
		t.Fatalf("terlalu banyak lolos: %d", lolos)
	}
}
