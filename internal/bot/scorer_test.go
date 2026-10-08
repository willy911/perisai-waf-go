package bot

import (
	"testing"
)

func TestScoreBrowserNormal(t *testing.T) {
	d := NewDetector(65, 90)
	// JA3 mirip browser: 12 ekstensi.
	ja3 := "771,4865-4866-4867,0-5-10-11-13-16-18-21-23-27-43-45,29-23-24,0"
	h := map[string]string{
		"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "id-ID,id;q=0.9",
	}
	score, _, action := d.Score(ja3, h)
	if action != "allow" || score != 0 {
		t.Fatalf("browser normal: score=%d action=%s, want 0/allow", score, action)
	}
}

func TestScoreUAPalsu(t *testing.T) {
	d := NewDetector(65, 90)
	// Mengaku Chrome tapi JA3 pendek khas curl -> mismatch (+40) -> challenge.
	ja3 := "771,4865-4866,0-23-65281-10-11,29-23,0"
	h := map[string]string{
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
		"accept":     "text/html",
	}
	score, signals, action := d.Score(ja3, h)
	if action != "challenge" {
		t.Fatalf("UA palsu: score=%d action=%s signals=%v, want challenge", score, action, signals)
	}
	found := false
	for _, s := range signals {
		if s == "ua-ja3-tidak-cocok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sinyal mismatch hilang: %v", signals)
	}
}

func TestScoreTanpaUA(t *testing.T) {
	d := NewDetector(65, 90)
	score, _, _ := d.Score("", map[string]string{})
	if score < 25 {
		t.Fatalf("tanpa UA mestinya >=25, dapat %d", score)
	}
}

func TestScoreFingerprintPernahMenyerang(t *testing.T) {
	d := NewDetector(65, 90)
	ja3 := "771,4865,0-10,29,0"
	h := map[string]string{"user-agent": "curl/8.0", "accept": "*/*"}
	d.Observe(ja3, true) // catat serangan
	score, _, action := d.Score(ja3, h)
	// 30 (ua-otomatis) + 35 (pernah menyerang) = 65 -> challenge
	if action != "challenge" || score != 65 {
		t.Fatalf("got score=%d action=%s, want 65/challenge", score, action)
	}
}

func TestScoreFingerprintTerpercaya(t *testing.T) {
	d := NewDetector(65, 90)
	ja3 := "771,4865,0-10,29,0"
	h := map[string]string{"user-agent": "curl/8.0", "accept": "*/*"}
	d.Observe(ja3, true)
	for i := 0; i < 3; i++ {
		d.ChallengePassed(ja3)
	}
	score, _, action := d.Score(ja3, h)
	// 30 + 35 - 30 = 35 -> allow (manusia terverifikasi challenge)
	if action != "allow" {
		t.Fatalf("fingerprint terpercaya: score=%d action=%s, want allow", score, action)
	}
}

func TestScoreBlockAmbang(t *testing.T) {
	d := NewDetector(65, 90)
	ja3 := "771,4865,0-10,29,0"
	d.Observe(ja3, true)
	// UA palsu (70) + pernah menyerang (35) + tanpa accept (10) = 115 -> 100 -> block.
	// Kombinasi penipuan + riwayat serangan memang layak diblokir langsung.
	_, _, action := d.Score(ja3, map[string]string{
		"user-agent": "Mozilla/5.0 Chrome/120.0", // browser UA + JA3 pendek
	})
	if action != "block" {
		t.Fatalf("got action=%s, want block", action)
	}
	// Skor tidak boleh melebihi 100.
	score, _, _ := d.Score(ja3, map[string]string{"user-agent": "x"})
	if score > 100 || score < 0 {
		t.Fatalf("skor di luar 0..100: %d", score)
	}
}
