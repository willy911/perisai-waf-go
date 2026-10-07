// Test IPLists: port vektor dari tests/test_defense.py & tests/test_ipgroups.py
// (Python).
package iplists

import (
	"testing"
	"time"

	"github.com/willy911/perisai-waf/internal/storage"
)

func newTestIPLists(t *testing.T) (*IPLists, *storage.Storage) {
	t.Helper()
	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st), st
}

// addEntry meniru IPLists.add() Python: network dinormalisasi seperti
// ip_network(strict=False), id acak 12 hex.
func addEntry(t *testing.T, st *storage.Storage, network, list, scope string, expiresAt any) {
	t.Helper()
	p, ok := parseCIDR(network)
	if !ok {
		t.Fatalf("CIDR tidak valid: %q", network)
	}
	if err := st.UpsertIPEntry(map[string]any{
		"id":         "test-entry",
		"network":    p.String(),
		"list":       list,
		"scope":      scope,
		"note":       "",
		"expires_at": expiresAt,
	}); err != nil {
		t.Fatalf("UpsertIPEntry: %v", err)
	}
}

// TestWhiteCIDRAndBlackSingleIP: tambah entry white 203.0.113.0/24 ->
// IsWhitelisted("203.0.113.7") true, IsBlacklisted false.
func TestWhiteCIDRAndBlackSingleIP(t *testing.T) {
	l, st := newTestIPLists(t)
	addEntry(t, st, "203.0.113.0/24", "white", "global", nil)
	l.Invalidate()

	if !l.IsWhitelisted("203.0.113.7") {
		t.Error("IsWhitelisted(203.0.113.7) = false, ingin true")
	}
	if l.IsBlacklisted("203.0.113.7") {
		t.Error("IsBlacklisted(203.0.113.7) = true, ingin false")
	}
}

// TestBlackSpecificIP: entry black untuk IP spesifik -> IsBlacklisted true.
func TestBlackSpecificIP(t *testing.T) {
	l, st := newTestIPLists(t)
	addEntry(t, st, "198.51.100.9", "black", "global", nil) // dinormalisasi /32
	l.Invalidate()

	if !l.IsBlacklisted("198.51.100.9") {
		t.Error("IsBlacklisted(198.51.100.9) = false, ingin true")
	}
	if l.IsBlacklisted("198.51.100.10") {
		t.Error("IsBlacklisted(198.51.100.10) = true, ingin false")
	}
}

// TestUnknownIP: IP tak dikenal -> keduanya false (vektor: 10.0.1.9, bukan-ip).
func TestUnknownIP(t *testing.T) {
	l, st := newTestIPLists(t)
	addEntry(t, st, "10.0.0.0/24", "black", "global", nil)
	l.Invalidate()

	for _, ip := range []string{"10.0.1.9", "bukan-ip", ""} {
		if l.IsWhitelisted(ip) {
			t.Errorf("IsWhitelisted(%q) = true, ingin false", ip)
		}
		if l.IsBlacklisted(ip) {
			t.Errorf("IsBlacklisted(%q) = true, ingin false", ip)
		}
	}
}

// TestWhitelistBeatsBlacklist: overlap white atas black -> whitelist menang
// (vektor Python: black 10.0.0.0/24 + white 10.0.0.5).
func TestWhitelistBeatsBlacklist(t *testing.T) {
	l, st := newTestIPLists(t)
	addEntry(t, st, "10.0.0.0/24", "black", "global", nil)
	if err := st.UpsertIPEntry(map[string]any{
		"id": "white-entry", "network": "10.0.0.5/32",
		"list": "white", "scope": "global", "expires_at": nil,
	}); err != nil {
		t.Fatalf("UpsertIPEntry: %v", err)
	}
	l.Invalidate()

	if !l.IsWhitelisted("10.0.0.5") {
		t.Error("IsWhitelisted(10.0.0.5) = false, ingin true")
	}
	if l.IsBlacklisted("10.0.0.5") {
		t.Error("IsBlacklisted(10.0.0.5) = true, whitelist harus menang")
	}
	if !l.IsBlacklisted("10.0.0.9") {
		t.Error("IsBlacklisted(10.0.0.9) = false, ingin true (kena CIDR)")
	}
}

// TestGroupWhiteBlack: grup white/black dikenakan seperti entri manual,
// whitelist grup menang atas blacklist grup (vektor test_ipgroups.py).
func TestGroupWhiteBlack(t *testing.T) {
	l, st := newTestIPLists(t)

	gb, err := st.CreateIPGroup("Penyerang", "black", "")
	if err != nil {
		t.Fatalf("CreateIPGroup: %v", err)
	}
	if _, err := st.AddGroupMember(gb, "10.9.9.0/24"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	l.Invalidate()

	if !l.IsBlacklisted("10.9.9.5") {
		t.Error("IsBlacklisted(10.9.9.5) = false, ingin true (grup black)")
	}
	if l.IsBlacklisted("10.9.8.5") {
		t.Error("IsBlacklisted(10.9.8.5) = true, ingin false")
	}

	gw, err := st.CreateIPGroup("VIP", "white", "")
	if err != nil {
		t.Fatalf("CreateIPGroup: %v", err)
	}
	if _, err := st.AddGroupMember(gw, "10.9.9.5"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	l.Invalidate()

	if !l.IsWhitelisted("10.9.9.5") {
		t.Error("IsWhitelisted(10.9.9.5) = false, ingin true (grup white)")
	}
	if l.IsBlacklisted("10.9.9.5") {
		t.Error("IsBlacklisted(10.9.9.5) = true, whitelist grup harus menang")
	}
}

// TestInvalidateReload: Invalidate() memuat ulang setelah entry baru ditambah.
func TestInvalidateReload(t *testing.T) {
	l, st := newTestIPLists(t)
	if l.IsBlacklisted("7.7.7.7") {
		t.Fatal("pra-kondisi gagal: 7.7.7.7 sudah blacklist sebelum ada entry")
	}
	addEntry(t, st, "7.7.0.0/16", "black", "global", nil)
	// tanpa Invalidate, cache lama tetap dipakai -> masih false
	if l.IsBlacklisted("7.7.7.7") {
		t.Error("cache seharusnya basi sebelum Invalidate()")
	}
	l.Invalidate()
	if !l.IsBlacklisted("7.7.7.7") {
		t.Error("IsBlacklisted(7.7.7.7) = false setelah Invalidate, ingin true")
	}
}

// TestExpiry: entri kedaluwarsa dilewati (vektor test_iplist_expiry).
func TestExpiry(t *testing.T) {
	l, st := newTestIPLists(t)
	addEntry(t, st, "9.9.9.9", "black", "global",
		float64(time.Now().UnixNano())/1e9+1.5) // kedaluwarsa ~1.5 detik
	l.Invalidate()
	if !l.IsBlacklisted("9.9.9.9") {
		t.Fatal("IsBlacklisted(9.9.9.9) = false sebelum kedaluwarsa")
	}
	time.Sleep(2 * time.Second)
	if l.IsBlacklisted("9.9.9.9") {
		t.Error("IsBlacklisted(9.9.9.9) = true setelah kedaluwarsa, ingin false")
	}
}

// TestScope: entri scope non-global dilewati bila site tidak cocok.
// (check(ip, siteID) internal dipakai karena kontrak publik tanpa site.)
func TestScope(t *testing.T) {
	l, st := newTestIPLists(t)
	if err := st.UpsertIPEntry(map[string]any{
		"id": "scoped", "network": "192.0.2.0/24",
		"list": "black", "scope": "site-abc", "expires_at": nil,
	}); err != nil {
		t.Fatalf("UpsertIPEntry: %v", err)
	}
	l.Invalidate()

	if l.check("192.0.2.9", "") == "black" {
		t.Error("check dengan siteID kosong harus melewati scope site-abc")
	}
	if l.check("192.0.2.9", "site-abc") != "black" {
		t.Error("check dengan siteID cocok harus black")
	}
	if l.check("192.0.2.9", "site-lain") == "black" {
		t.Error("check dengan siteID lain harus melewati")
	}
}

// TestInvalidEntrySkipped: entri dengan CIDR rusak di DB dilewati, tidak crash.
func TestInvalidEntrySkipped(t *testing.T) {
	l, st := newTestIPLists(t)
	// tulis langsung tanpa validasi lewat SQL mentah
	if _, err := st.DB.Exec(
		`INSERT INTO ip_lists (id, network, list, scope, created_at)
		 VALUES ('rusak', 'bukan-cidr', 'black', 'global', 0)`); err != nil {
		t.Fatalf("insert mentah: %v", err)
	}
	l.Invalidate()
	if l.IsBlacklisted("1.2.3.4") {
		t.Error("entri rusak tidak boleh mem-blacklist siapa pun")
	}
}
