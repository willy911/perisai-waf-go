package reputation

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/storage"
)

// newTestRep membuat Reputation dengan storage di t.TempDir() dan
// ambang kecil agar test tidak perlu menunggu lama.
func newTestRep(t *testing.T, cfg config.ReputationConfig) (*Reputation, *storage.Storage) {
	t.Helper()
	s, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(cfg, s), s
}

func quickCfg() config.ReputationConfig {
	return config.ReputationConfig{
		Enabled: true, StrikesToBlock: 3, WindowSeconds: 2, BlockSeconds: 2,
	}
}

func TestCheckCleanIP(t *testing.T) {
	r, _ := newTestRep(t, quickCfg())
	if r.Check("203.0.113.7") {
		t.Fatal("IP bersih (belum pernah tercatat) tidak boleh diblokir")
	}
}

func TestDisabledNeverBlocks(t *testing.T) {
	cfg := quickCfg()
	cfg.Enabled = false
	r, _ := newTestRep(t, cfg)
	for i := 0; i < 10; i++ {
		r.RecordBlock("203.0.113.8")
	}
	if r.Check("203.0.113.8") {
		t.Fatal("reputation dinonaktifkan: tidak boleh ada blokir")
	}
}

func TestStrikesToBlock(t *testing.T) {
	r, _ := newTestRep(t, quickCfg())
	ip := "203.0.113.9"
	r.RecordBlock(ip)
	if r.Check(ip) {
		t.Fatal("1 strike < strikes_to_block: tidak boleh diblokir")
	}
	r.RecordBlock(ip)
	if r.Check(ip) {
		t.Fatal("2 strike < strikes_to_block: tidak boleh diblokir")
	}
	r.RecordBlock(ip)
	if !r.Check(ip) {
		t.Fatal("3 strike >= strikes_to_block: harus diblokir")
	}
}

func TestBlockExpires(t *testing.T) {
	r, s := newTestRep(t, quickCfg())
	ip := "203.0.113.10"
	for i := 0; i < 3; i++ {
		r.RecordBlock(ip)
	}
	if !r.Check(ip) {
		t.Fatal("IP harus diblokir sebelum masa berlaku habis")
	}
	// block_seconds = 2, tunggu lewat sedikit
	time.Sleep(2200 * time.Millisecond)
	if r.Check(ip) {
		t.Fatal("setelah block_seconds berlalu IP tidak boleh diblokir lagi")
	}
	// Check harusnya me-reset strikes ke 0 (seperti Python)
	rec, err := s.GetIP(ip)
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if rec["strikes"] != int64(0) {
		t.Fatalf("strikes setelah blokir kedaluwarsa = %v, ingin 0", rec["strikes"])
	}
	if v, ok := rec["blocked_until"]; ok && v != nil {
		if f, isFloat := v.(float64); isFloat && f != 0 {
			t.Fatalf("blocked_until setelah kedaluwarsa = %v, ingin NULL", f)
		}
	}
}

func TestWindowExpiryResetsStrikes(t *testing.T) {
	r, s := newTestRep(t, quickCfg())
	ip := "203.0.113.11"
	r.RecordBlock(ip)
	// window_seconds = 2, biarkan window kedaluwarsa
	time.Sleep(2200 * time.Millisecond)
	// strike baru setelah window kedaluwarsa: harus dihitung sebagai strike 1
	// (bukan 2), jadi belum diblokir
	r.RecordBlock(ip)
	if r.Check(ip) {
		t.Fatal("strike di luar window harus me-reset hitungan, bukan akumulasi")
	}
	rec, err := s.GetIP(ip)
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if rec["strikes"] != int64(1) {
		t.Fatalf("strikes = %v, ingin 1 (reset window)", rec["strikes"])
	}
}

func TestStrikesAccumulateWithinWindow(t *testing.T) {
	r, s := newTestRep(t, quickCfg())
	ip := "203.0.113.12"
	r.RecordBlock(ip)
	time.Sleep(300 * time.Millisecond) // masih di dalam window
	r.RecordBlock(ip)
	rec, err := s.GetIP(ip)
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if rec["strikes"] != int64(2) {
		t.Fatalf("strikes = %v, ingin 2 (akumulasi dalam window)", rec["strikes"])
	}
}

func TestGetIPNoRowsForNewIP(t *testing.T) {
	_, s := newTestRep(t, quickCfg())
	_, err := s.GetIP("203.0.113.99")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("IP baru harus menghasilkan sql.ErrNoRows, dapat: %v", err)
	}
}

func TestNewIsolation(t *testing.T) {
	r, _ := newTestRep(t, quickCfg())
	bad, good := "203.0.113.20", "203.0.113.21"
	for i := 0; i < 3; i++ {
		r.RecordBlock(bad)
	}
	if !r.Check(bad) {
		t.Fatal("IP jahat harus diblokir")
	}
	if r.Check(good) {
		t.Fatal("IP lain tidak boleh ikut diblokir")
	}
}
