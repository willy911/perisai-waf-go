package bot

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// profile adalah catatan perilaku satu fingerprint JA3.
type profile struct {
	firstSeen time.Time
	lastSeen  time.Time
	requests  int
	attacks   int // request dengan temuan engine
	chalOK    int // lolos challenge
	chalFail  int // gagal/tidak pernah menyelesaikan challenge
}

// Detector menilai "kebot-an" sebuah request dari fingerprint TLS/JA3 +
// sinyal HTTP. Terinspirasi anti-bot proaktif SafeLine.
type Detector struct {
	challengeScore int
	blockScore     int
	mu             sync.Mutex
	profiles       map[string]*profile
	sweepTick      int
}

// NewDetector membuat detector dari ambang konfigurasi.
func NewDetector(challengeScore, blockScore int) *Detector {
	if challengeScore <= 0 {
		challengeScore = 65
	}
	if blockScore <= 0 {
		blockScore = 90
	}
	return &Detector{
		challengeScore: challengeScore,
		blockScore:     blockScore,
		profiles:       make(map[string]*profile),
	}
}

// automationUA melaporkan UA khas tool otomatis (bukan browser manusia).
func automationUA(ua string) bool {
	u := strings.ToLower(ua)
	for _, s := range []string{"curl", "wget", "python-requests", "python-urllib",
		"go-http-client", "postmanruntime", "java/", "libwww-perl", "httpclient",
		"okhttp", "axios", "node-fetch"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

// browserUA melaporkan UA yang mengaku sebagai browser desktop/mobile umum.
func browserUA(ua string) bool {
	u := strings.ToLower(ua)
	if automationUA(ua) {
		return false
	}
	for _, s := range []string{"chrome/", "firefox/", "safari/", "edg/", "opr/",
		"mobile safari", "android", "iphone", "ipad"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

// browserLikeJA3: JA3 browser asli umumnya membawa >=10 ekstensi; klien
// otomatis (curl, Go, python) biasanya <8. Heuristik murah tanpa daftar hash.
func browserLikeJA3(ja3 string) bool {
	parts := strings.Split(ja3, ",")
	if len(parts) < 3 || parts[2] == "" {
		return false
	}
	return len(strings.Split(parts[2], "-")) >= 10
}

// browserCipherOrder: browser modern selalu mengurutkan cipher TLS 1.3 di
// depan dengan pola khas — Chromium: 4865-4866-4867, Firefox: 4865-4867-4866.
// Klien OpenSSL (curl, python-requests, wget) memakai 4866-4867-4865.
// Terkalibrasi dari capture live (curl OpenSSL -> 4866-4867-4865-...).
func browserCipherOrder(ja3 string) bool {
	parts := strings.Split(ja3, ",")
	if len(parts) < 2 {
		return false
	}
	c := parts[1]
	return strings.HasPrefix(c, "4865-4866-4867") ||
		strings.HasPrefix(c, "4865-4867-4866")
}

// fpKey mengubah string JA3 menjadi kunci profil (md5 hex, ringkas).
func fpKey(ja3 string) string {
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// Score menilai request (0-100) dan mengembalikan aksi: allow|challenge|block
// beserta nama-nama sinyal yang menyumbang skor. headers memakai key
// lowercase (seperti flattenHeaders proxy). ja3 boleh "" (non-TLS).
func (d *Detector) Score(ja3 string, headers map[string]string) (int, []string, string) {
	ua := headers["user-agent"]
	score := 0
	var signals []string
	add := func(name string, pts int) {
		score += pts
		signals = append(signals, name)
	}

	// -- sinyal header (berlaku juga tanpa TLS/JA3) --
	if ua == "" {
		add("tanpa-user-agent", 25)
	} else if automationUA(ua) {
		add("ua-otomatis", 30)
	}
	if headers["accept"] == "" && headers["accept-language"] == "" {
		add("tanpa-header-accept", 10)
	}

	// -- sinyal JA3 --
	if ja3 != "" {
		if browserUA(ua) && (!browserLikeJA3(ja3) || !browserCipherOrder(ja3)) {
			// Sinyal terkuat: mengaku Chrome/Firefox tapi handshake-nya
			// khas tool otomatis -> UA dipalsukan (penipuan deliberate).
			add("ua-ja3-tidak-cocok", 70)
		}
		d.mu.Lock()
		key := fpKey(ja3)
		p, ok := d.profiles[key]
		if !ok {
			p = &profile{firstSeen: time.Now()}
			d.profiles[key] = p
		}
		p.lastSeen = time.Now()
		p.requests++
		if p.attacks > 0 {
			add("fingerprint-pernah-menyerang", 35)
		}
		// Fingerprint baru (<5 menit) yang langsung tancap gas.
		if time.Since(p.firstSeen) < 5*time.Minute && p.requests > 20 {
			add("fingerprint-baru-agresif", 20)
		}
		// Fingerprint yang sudah berulang kali lolos challenge = manusia.
		if p.chalOK >= 3 {
			score -= 30
			signals = append(signals, "fingerprint-terpercaya")
		}
		d.sweepTick++
		if d.sweepTick%500 == 0 {
			d.sweep()
		}
		d.mu.Unlock()
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	action := "allow"
	switch {
	case score >= d.blockScore:
		action = "block"
	case score >= d.challengeScore:
		action = "challenge"
	}
	return score, signals, action
}

// Observe mencatat hasil triase engine untuk fingerprint ini; dipanggil
// sekali per request setelah engine berjalan.
func (d *Detector) Observe(ja3 string, attacked bool) {
	if ja3 == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := fpKey(ja3)
	p, ok := d.profiles[key]
	if !ok {
		p = &profile{firstSeen: time.Now(), lastSeen: time.Now()}
		d.profiles[key] = p
	}
	if attacked {
		p.attacks++
	}
}

// ChallengePassed mencatat fingerprint yang menyelesaikan challenge
// (terlihat dari cookie challenge valid) -> dipercaya.
func (d *Detector) ChallengePassed(ja3 string) {
	if ja3 == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := fpKey(ja3)
	p, ok := d.profiles[key]
	if !ok {
		p = &profile{firstSeen: time.Now(), lastSeen: time.Now()}
		d.profiles[key] = p
	}
	p.chalOK++
}

// sweep membuang profil yang tidak terlihat >24 jam (dipanggil oportunistik).
func (d *Detector) sweep() {
	cutoff := time.Now().Add(-24 * time.Hour)
	for k, p := range d.profiles {
		if p.lastSeen.Before(cutoff) {
			delete(d.profiles, k)
		}
	}
}
