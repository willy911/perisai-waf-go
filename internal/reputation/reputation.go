// Package reputation melacak reputasi IP: strike counter + blokir sementara
// otomatis. Merupakan port dari perisai/reputation.py (Python).
package reputation

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/storage"
)

// Reputation mencatat strike untuk tiap request yang di-block. Bila sebuah IP
// mencapai strikes_to_block di dalam window_seconds, IP diblokir sementara
// selama block_seconds.
type Reputation struct {
	cfg   config.ReputationConfig
	store *storage.Storage
	// mu mengunci operasi baca-modifikasi-tulis di RecordBlock agar dua
	// strike bersamaan dari goroutine berbeda tidak saling menimpa.
	// (Metode storage sudah dikunci mutex masing-masing.)
	mu sync.Mutex
}

// New membuat pelacak reputasi baru dari konfigurasi dan penyimpanan.
func New(cfg config.ReputationConfig, store *storage.Storage) *Reputation {
	return &Reputation{cfg: cfg, store: store}
}

// Check memeriksa apakah ip sedang diblokir sementara. Bila blokir sudah
// kedaluwarsa, catatan IP di-reset (strikes=0, window baru) seperti Python.
func (r *Reputation) Check(ip string) (blocked bool) {
	if !r.cfg.Enabled {
		return false
	}
	rec, err := r.store.GetIP(ip)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false // IP belum pernah tercatat: bersih
		}
		return false // error DB: jangan blokir (fail open)
	}
	blockedUntil := floatVal(rec["blocked_until"])
	if blockedUntil == 0 {
		return false
	}
	now := nowSec()
	if blockedUntil > now {
		return true
	}
	// blokir kedaluwarsa -> reset strikes & window
	_ = r.store.UpsertIP(ip, 0, now, nil)
	return false
}

// RecordBlock mencatat satu strike untuk ip. Dipanggil setiap ada keputusan
// block dari engine/agent (port dari Python: record(ip, blocked=True)).
// Keputusan bukan-block tidak menambah strike. Bila strike mencapai
// strikes_to_block di dalam window, ip diblokir selama block_seconds.
func (r *Reputation) RecordBlock(ip string) {
	if !r.cfg.Enabled {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := nowSec()
	strikes := 1
	windowStart := now
	rec, err := r.store.GetIP(ip)
	if err == nil {
		ws := floatVal(rec["window_start"])
		if now-ws < float64(r.cfg.WindowSeconds) {
			// masih di dalam window: akumulasi strike
			strikes = intVal(rec["strikes"]) + 1
			windowStart = ws
		}
		// window kedaluwarsa -> strike di-reset ke 1, window baru (seperti Python)
	}
	var blockedUntil *float64
	if strikes >= r.cfg.StrikesToBlock {
		bu := now + float64(r.cfg.BlockSeconds)
		blockedUntil = &bu
	}
	_ = r.store.UpsertIP(ip, strikes, windowStart, blockedUntil)
}

func nowSec() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// floatVal mengubah nilai kolom map[string]any menjadi float64.
// NULL/tipe tak dikenal -> 0 (sama seperti `or 0` di Python).
func floatVal(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int64:
		return float64(t)
	case int:
		return float64(t)
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func intVal(v any) int {
	switch t := v.(type) {
	case int64:
		return int(t)
	case int:
		return t
	case float64:
		return int(t)
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return 0
	}
}
