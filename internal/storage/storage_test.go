package storage

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestStorage membuat Storage baru di direktori sementara.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateTablesExist(t *testing.T) {
	s := newTestStorage(t)
	want := []string{
		"requests", "agent_runs", "proposed_rules", "ip_reputation",
		"sites", "ip_lists", "geo_cache", "ip_groups",
		"ip_group_members", "settings",
	}
	for _, tbl := range want {
		var name string
		err := s.DB.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl).Scan(&name)
		if err != nil {
			t.Errorf("tabel %s tidak ada: %v", tbl, err)
		}
	}
	// kolom tambahan dari _ensure_column harus ada
	for _, col := range []string{"site_id"} {
		var name string
		err := s.DB.QueryRow(
			"SELECT name FROM pragma_table_info('requests') WHERE name=?", col).Scan(&name)
		if err != nil {
			t.Errorf("kolom requests.%s tidak ada: %v", col, err)
		}
	}
	for _, col := range []string{"ddos_mode", "ddos_rps", "cache_enabled", "cf_zone_id", "recaptcha_enabled"} {
		var name string
		err := s.DB.QueryRow(
			"SELECT name FROM pragma_table_info('sites') WHERE name=?", col).Scan(&name)
		if err != nil {
			t.Errorf("kolom sites.%s tidak ada: %v", col, err)
		}
	}
}

// TestSiteCRUD mem port test_site_crud dari tests/test_sites.py (Python).
func TestSiteCRUD(t *testing.T) {
	s := newTestStorage(t)

	sid, err := s.UpsertSite(map[string]any{
		"domain": "TokoKu.com", "upstream_host": "10.0.0.1", "upstream_port": 9000,
	})
	if err != nil {
		t.Fatalf("UpsertSite: %v", err)
	}
	if sid == "" {
		t.Fatal("id site kosong")
	}
	got, err := s.GetSiteByDomain("tokoku.com") // domain dinormalisasi
	if err != nil {
		t.Fatalf("GetSiteByDomain: %v", err)
	}
	if toString(got["id"], "") != sid {
		t.Errorf("id = %v, want %v", got["id"], sid)
	}

	sites, err := s.ListSites()
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("ListSites = %d, want 1", len(sites))
	}

	_, err = s.UpsertSite(map[string]any{
		"id": sid, "domain": "tokoku.com", "upstream_host": "10.0.0.2",
		"upstream_port": 9001, "enabled": 0,
	})
	if err != nil {
		t.Fatalf("UpsertSite update: %v", err)
	}
	got, err = s.GetSite(sid)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if toInt(got["upstream_port"], 0) != 9001 {
		t.Errorf("upstream_port = %v, want 9001", got["upstream_port"])
	}
	if toInt(got["enabled"], 1) != 0 {
		t.Errorf("enabled = %v, want 0", got["enabled"])
	}

	// default kolom saat insert baru
	if toInt(got["preserve_host"], 0) != 1 {
		t.Errorf("preserve_host default = %v, want 1", got["preserve_host"])
	}

	if err := s.DeleteSite(sid); err != nil {
		t.Fatalf("DeleteSite: %v", err)
	}
	sites, _ = s.ListSites()
	if len(sites) != 0 {
		t.Errorf("ListSites setelah delete = %d, want 0", len(sites))
	}
	if _, err := s.GetSite(sid); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetSite setelah delete err = %v, want ErrNoRows", err)
	}
	if _, err := s.GetSiteByDomain("unknown.test"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetSiteByDomain unknown err = %v, want ErrNoRows", err)
	}
}

func TestSiteDefaults(t *testing.T) {
	s := newTestStorage(t)
	sid, err := s.UpsertSite(map[string]any{"domain": "A.com"})
	if err != nil {
		t.Fatalf("UpsertSite: %v", err)
	}
	got, err := s.GetSite(sid)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if toString(got["domain"], "") != "a.com" {
		t.Errorf("domain = %v, want a.com", got["domain"])
	}
	if toInt(got["enabled"], 0) != 1 || toInt(got["agent_enabled"], 0) != 1 {
		t.Errorf("enabled/agent_enabled default salah: %v %v", got["enabled"], got["agent_enabled"])
	}
	if toString(got["disabled_rules"], "") != "[]" {
		t.Errorf("disabled_rules default = %v, want []", got["disabled_rules"])
	}
	if toInt(got["upstream_port"], 0) != 8000 {
		t.Errorf("upstream_port default = %v, want 8000", got["upstream_port"])
	}
	if toFloat(got["ddos_rps"], 0) != 5 {
		t.Errorf("ddos_rps default = %v, want 5", got["ddos_rps"])
	}
}

func TestSiteDisabledRulesList(t *testing.T) {
	s := newTestStorage(t)
	sid, err := s.UpsertSite(map[string]any{
		"domain": "b.test", "disabled_rules": []string{"XSS-001"},
		"cache_bypass_cookies": []string{"sess"},
	})
	if err != nil {
		t.Fatalf("UpsertSite: %v", err)
	}
	got, _ := s.GetSite(sid)
	if toString(got["disabled_rules"], "") != `["XSS-001"]` {
		t.Errorf("disabled_rules = %v", got["disabled_rules"])
	}
	if toString(got["cache_bypass_cookies"], "") != `["sess"]` {
		t.Errorf("cache_bypass_cookies = %v", got["cache_bypass_cookies"])
	}
}

func TestLogRequestRecentStats(t *testing.T) {
	s := newTestStorage(t)
	now := float64(time.Now().Unix())

	// site_id untuk uji filter
	sid, _ := s.UpsertSite(map[string]any{"domain": "a.test"})

	logs := []struct{ id, ip, decision, rule, site string }{
		{"r1", "1.1.1.1", "allow", "", ""},
		{"r2", "2.2.2.2", "block", "XSS-001", ""},
		{"r3", "2.2.2.2", "block", "XSS-001", sid},
		{"r4", "3.3.3.3", "challenge", "SQLI-002", sid},
		{"r5", "2.2.2.2", "block", "XSS-001", ""},
	}
	for _, l := range logs {
		if err := s.LogRequest(l.id, now, l.ip, "GET", "/x", "q=1",
			0, l.decision, 0, 1.5, l.rule, l.site); err != nil {
			t.Fatalf("LogRequest: %v", err)
		}
	}

	recent, err := s.RecentRequests(100, "")
	if err != nil {
		t.Fatalf("RecentRequests: %v", err)
	}
	if len(recent) != 5 {
		t.Fatalf("RecentRequests = %d, want 5", len(recent))
	}
	// path/query dipotong 500 char — uji dengan string panjang
	longStr := ""
	for i := 0; i < 600; i++ {
		longStr += "a"
	}
	if err := s.LogRequest("rlong", now, "9.9.9.9", "GET", longStr, longStr,
		0, "allow", 0, 1, "", ""); err != nil {
		t.Fatalf("LogRequest long: %v", err)
	}
	recent, _ = s.RecentRequests(1, "")
	if len(toString(recent[0]["path"], "")) != 500 {
		t.Errorf("path tidak dipotong 500: len=%d", len(toString(recent[0]["path"], "")))
	}

	// filter site_id
	bySite, err := s.RecentRequests(100, sid)
	if err != nil {
		t.Fatalf("RecentRequests site: %v", err)
	}
	if len(bySite) != 2 {
		t.Errorf("RecentRequests(site) = %d, want 2", len(bySite))
	}

	stats, err := s.Stats(now - 3600)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["total"] != int64(6) {
		t.Errorf("total = %v, want 6", stats["total"])
	}
	bd := stats["by_decision"].(map[string]any)
	if toInt64(bd["block"]) != 3 {
		t.Errorf("by_decision[block] = %v, want 3", bd["block"])
	}
	tr := stats["top_rules"].([]map[string]any)
	if len(tr) == 0 || toString(tr[0]["rule"], "") != "XSS-001" || toInt64(tr[0]["count"]) != 3 {
		t.Errorf("top_rules salah: %v", tr)
	}
	to := stats["top_offenders"].([]map[string]any)
	if len(to) == 0 || toString(to[0]["ip"], "") != "2.2.2.2" {
		t.Errorf("top_offenders salah: %v", to)
	}

	counts, err := s.RequestCountsBySite(now - 3600)
	if err != nil {
		t.Fatalf("RequestCountsBySite: %v", err)
	}
	if counts[sid] != 2 {
		t.Errorf("counts[%s] = %d, want 2", sid, counts[sid])
	}

	blocked, err := s.RecentBlockedIPs(now-3600, 200)
	if err != nil {
		t.Fatalf("RecentBlockedIPs: %v", err)
	}
	if len(blocked) != 1 || toString(blocked[0]["ip"], "") != "2.2.2.2" ||
		toInt64(blocked[0]["count"]) != 3 {
		t.Errorf("RecentBlockedIPs salah: %v", blocked)
	}
}

func TestAgentRuns(t *testing.T) {
	s := newTestStorage(t)
	reasoning := []any{"pola mencurigakan", "skor 42"}
	indicators := []any{"xss", "sqli"}
	id, err := s.LogAgentRun("req-1", "heuristic", "challenge", 0.7, reasoning, indicators, 12.5)
	if err != nil {
		t.Fatalf("LogAgentRun: %v", err)
	}
	if id == 0 {
		t.Error("lastrowid = 0")
	}
	runs, err := s.RecentAgentRuns(50)
	if err != nil {
		t.Fatalf("RecentAgentRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	r := runs[0]
	if toString(r["backend"], "") != "heuristic" || toString(r["decision"], "") != "challenge" {
		t.Errorf("run salah: %v", r)
	}
	rj, ok := r["reasoning"].([]any)
	if !ok || len(rj) != 2 || rj[0] != "pola mencurigakan" {
		t.Errorf("reasoning tidak ter-decode: %v", r["reasoning"])
	}
	ij, ok := r["indicators"].([]any)
	if !ok || len(ij) != 2 {
		t.Errorf("indicators tidak ter-decode: %v", r["indicators"])
	}
}

func TestProposedRules(t *testing.T) {
	s := newTestStorage(t)
	rule := map[string]any{"id": "AI-001", "pattern": "evil", "severity": "high"}
	pid, err := s.ProposeRule(rule, "ai-agent", "confidence=0.90")
	if err != nil {
		t.Fatalf("ProposeRule: %v", err)
	}
	pending, err := s.ListProposed("pending")
	if err != nil {
		t.Fatalf("ListProposed: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	got, ok := pending[0]["rule"].(map[string]any)
	if !ok || toString(got["id"], "") != "AI-001" {
		t.Errorf("rule tidak ter-decode: %v", pending[0]["rule"])
	}
	if toString(pending[0]["source"], "") != "ai-agent" {
		t.Errorf("source = %v", pending[0]["source"])
	}

	if err := s.SetProposedStatus(pid, "approved"); err != nil {
		t.Fatalf("SetProposedStatus: %v", err)
	}
	pending, _ = s.ListProposed("pending")
	if len(pending) != 0 {
		t.Errorf("pending setelah approve = %d, want 0", len(pending))
	}
	approved, _ := s.ListProposed("approved")
	if len(approved) != 1 {
		t.Errorf("approved = %d, want 1", len(approved))
	}
}

func TestIPEntriesCRUD(t *testing.T) {
	s := newTestStorage(t)
	if err := s.UpsertIPEntry(map[string]any{
		"id": "e1", "network": "10.0.0.0/8", "list": "black",
		"scope": "global", "note": "test", "expires_at": nil,
	}); err != nil {
		t.Fatalf("UpsertIPEntry: %v", err)
	}
	entries, err := s.ListIPEntries()
	if err != nil {
		t.Fatalf("ListIPEntries: %v", err)
	}
	if len(entries) != 1 || toString(entries[0]["network"], "") != "10.0.0.0/8" {
		t.Fatalf("entries salah: %v", entries)
	}
	if entries[0]["expires_at"] != nil {
		t.Errorf("expires_at = %v, want NULL", entries[0]["expires_at"])
	}

	// update via upsert yang sama
	if err := s.UpsertIPEntry(map[string]any{
		"id": "e1", "network": "10.1.0.0/16", "list": "white", "note": "upd",
	}); err != nil {
		t.Fatalf("UpsertIPEntry update: %v", err)
	}
	entries, _ = s.ListIPEntries()
	if toString(entries[0]["network"], "") != "10.1.0.0/16" ||
		toString(entries[0]["list"], "") != "white" {
		t.Errorf("update gagal: %v", entries[0])
	}

	if err := s.DeleteIPEntry("e1"); err != nil {
		t.Fatalf("DeleteIPEntry: %v", err)
	}
	entries, _ = s.ListIPEntries()
	if len(entries) != 0 {
		t.Errorf("entries setelah delete = %d, want 0", len(entries))
	}
}

// TestIPGroupsCRUD mem port test_crud dari tests/test_ipgroups.py (Python).
func TestIPGroupsCRUD(t *testing.T) {
	s := newTestStorage(t)
	gid, err := s.CreateIPGroup("Kantor", "white", "IP kantor")
	if err != nil {
		t.Fatalf("CreateIPGroup: %v", err)
	}
	if gid == "" {
		t.Fatal("gid kosong")
	}
	groups, err := s.ListIPGroups()
	if err != nil {
		t.Fatalf("ListIPGroups: %v", err)
	}
	if len(groups) != 1 || toString(groups[0]["name"], "") != "Kantor" ||
		toString(groups[0]["kind"], "") != "white" {
		t.Fatalf("groups salah: %v", groups)
	}
	if mm, ok := groups[0]["members"].([]string); !ok || len(mm) != 0 {
		t.Errorf("members awal harus kosong: %v", groups[0]["members"])
	}

	// nama duplikat ditolak
	if _, err := s.CreateIPGroup("Kantor", "black", ""); err == nil {
		t.Error("nama duplikat tidak ditolak")
	}
	// kind tak valid ditolak
	if _, err := s.CreateIPGroup("X", "ungu", ""); err == nil {
		t.Error("kind tak valid tidak ditolak")
	}

	if _, err := s.AddGroupMember(gid, "203.0.113.0/24"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	norm, err := s.AddGroupMember(gid, "198.51.100.7") // jadi /32
	if err != nil {
		t.Fatalf("AddGroupMember ip: %v", err)
	}
	if norm != "198.51.100.7/32" {
		t.Errorf("normalisasi = %s, want 198.51.100.7/32", norm)
	}
	g, err := s.GetIPGroup(gid)
	if err != nil {
		t.Fatalf("GetIPGroup: %v", err)
	}
	mm := g["members"].([]string)
	if len(mm) != 2 || mm[0] != "198.51.100.7/32" || mm[1] != "203.0.113.0/24" {
		t.Errorf("members = %v, want terurut", mm)
	}

	// CIDR tak valid ditolak
	if _, err := s.AddGroupMember(gid, "ngaco"); err == nil {
		t.Error("CIDR tak valid tidak ditolak")
	}
	// grup tak ada ditolak
	if _, err := s.AddGroupMember("xxx", "1.2.3.4"); err == nil {
		t.Error("grup tak ada tidak ditolak")
	}

	desc := "baru"
	ok, err := s.UpdateIPGroup(gid, nil, &desc)
	if err != nil || !ok {
		t.Fatalf("UpdateIPGroup: ok=%v err=%v", ok, err)
	}
	g, _ = s.GetIPGroup(gid)
	if toString(g["description"], "") != "baru" {
		t.Errorf("description = %v", g["description"])
	}
	name := "y"
	ok, err = s.UpdateIPGroup("xxx", &name, nil)
	if err != nil || ok {
		t.Errorf("UpdateIPGroup grup tak ada: ok=%v err=%v", ok, err)
	}
	ok, err = s.UpdateIPGroup(gid, nil, nil)
	if err != nil || ok {
		t.Errorf("UpdateIPGroup tanpa field: ok=%v err=%v", ok, err)
	}

	if err := s.RemoveGroupMember(gid, "198.51.100.7/32"); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	g, _ = s.GetIPGroup(gid)
	if mm := g["members"].([]string); len(mm) != 1 || mm[0] != "203.0.113.0/24" {
		t.Errorf("members setelah hapus = %v", mm)
	}

	s.DeleteIPGroup(gid)
	groups, _ = s.ListIPGroups()
	if len(groups) != 0 {
		t.Errorf("groups setelah delete = %d", len(groups))
	}
	if _, err := s.GetIPGroup(gid); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetIPGroup setelah delete err = %v, want ErrNoRows", err)
	}
}

func TestReputation(t *testing.T) {
	s := newTestStorage(t)
	if _, err := s.GetIP("5.5.5.5"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetIP baru err = %v, want ErrNoRows", err)
	}
	if err := s.UpsertIP("5.5.5.5", 2, 1000.0, nil); err != nil {
		t.Fatalf("UpsertIP: %v", err)
	}
	got, err := s.GetIP("5.5.5.5")
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if toInt(got["strikes"], 0) != 2 || toFloat(got["window_start"], 0) != 1000.0 {
		t.Errorf("reputasi salah: %v", got)
	}
	if got["blocked_until"] != nil {
		t.Errorf("blocked_until = %v, want NULL", got["blocked_until"])
	}

	// update dengan blocked_until terisi
	bu := 2000.0
	if err := s.UpsertIP("5.5.5.5", 5, 1000.0, &bu); err != nil {
		t.Fatalf("UpsertIP update: %v", err)
	}
	got, _ = s.GetIP("5.5.5.5")
	if toInt(got["strikes"], 0) != 5 || toFloat(got["blocked_until"], 0) != 2000.0 {
		t.Errorf("reputasi setelah update salah: %v", got)
	}
}

func TestGeoCache(t *testing.T) {
	s := newTestStorage(t)
	if _, err := s.GeoGet("8.8.8.8"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GeoGet baru err = %v, want ErrNoRows", err)
	}
	lat, lon := -6.2, 106.8
	if err := s.GeoSet("8.8.8.8", "ID", "Jakarta", &lat, &lon); err != nil {
		t.Fatalf("GeoSet: %v", err)
	}
	got, err := s.GeoGet("8.8.8.8")
	if err != nil {
		t.Fatalf("GeoGet: %v", err)
	}
	if toString(got["country"], "") != "ID" || toString(got["city"], "") != "Jakarta" {
		t.Errorf("geo salah: %v", got)
	}
	if toFloat(got["lat"], 0) != lat || toFloat(got["lon"], 0) != lon {
		t.Errorf("lat/lon salah: %v", got)
	}

	// update dengan lat/lon nil
	if err := s.GeoSet("8.8.8.8", "ID", "Bandung", nil, nil); err != nil {
		t.Fatalf("GeoSet nil: %v", err)
	}
	got, _ = s.GeoGet("8.8.8.8")
	if got["lat"] != nil || got["lon"] != nil {
		t.Errorf("lat/lon harus NULL: %v", got)
	}
	if toString(got["city"], "") != "Bandung" {
		t.Errorf("city = %v, want Bandung", got["city"])
	}
}

func TestSettings(t *testing.T) {
	s := newTestStorage(t)
	v, err := s.GetSetting("belum_ada", "default123")
	if err != nil || v != "default123" {
		t.Fatalf("GetSetting default: v=%q err=%v", v, err)
	}
	if err := s.SetSetting("k1", "v1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, _ = s.GetSetting("k1", "")
	if v != "v1" {
		t.Errorf("GetSetting = %q, want v1", v)
	}
	if err := s.SetSetting("k1", "v2"); err != nil {
		t.Fatalf("SetSetting update: %v", err)
	}
	v, _ = s.GetSetting("k1", "")
	if v != "v2" {
		t.Errorf("GetSetting setelah update = %q, want v2", v)
	}
}

func TestListCustomRules(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	// file belum ada -> kosong, tanpa error
	rules, err := s.ListCustomRules()
	if err != nil || len(rules) != 0 {
		t.Fatalf("ListCustomRules kosong: %v %v", rules, err)
	}

	data := `[{"id":"AI-001","pattern":"evil","severity":"high"}]`
	if err := os.WriteFile(filepath.Join(dir, "custom_rules.json"),
		[]byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err = s.ListCustomRules()
	if err != nil {
		t.Fatalf("ListCustomRules: %v", err)
	}
	if len(rules) != 1 || toString(rules[0]["id"], "") != "AI-001" {
		t.Errorf("rules salah: %v", rules)
	}
}

func TestDBFileCreated(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "sub", "data"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(filepath.Join(dir, "sub", "data", "perisai.db")); err != nil {
		t.Errorf("perisai.db tidak dibuat: %v", err)
	}
}
