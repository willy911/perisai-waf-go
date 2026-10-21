package dashboard

// Test endpoint MCP (POST /mcp): JSON-RPC initialize/tools/list/
// tools/call dengan token dashboard; tanpa token -> 401; notifikasi
// -> 202 tanpa body.

import (
	"encoding/json"
	"testing"
)

// rpcCall mengirim satu request JSON-RPC dan mengembalikan respons
// ter-decode.
func (s *testSetup) rpcCall(t *testing.T, body map[string]any, token string) (int, map[string]any) {
	t.Helper()
	code, raw := s.do(t, "POST", "/mcp", body, token)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("respons MCP bukan JSON: %q (status %d)", raw, code)
	}
	return code, m
}

// toolText mengekstrak teks JSON dari hasil tools/call dan men-decode-nya.
func toolText(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	res, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("result tidak ada: %v", m)
	}
	if res["isError"] == true {
		t.Fatalf("tool mengembalikan error: %v", res)
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("content kosong: %v", res)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("teks tool bukan JSON: %q", text)
	}
	return out
}

func TestMCPEndpoint(t *testing.T) {
	s := newTestSetup(t, testHash(t))
	initBody := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{},
	}

	// Tanpa token -> 401; token salah -> 401.
	if code, _ := s.do(t, "POST", "/mcp", initBody, ""); code != 401 {
		t.Fatalf("tanpa token: code=%d, mau 401", code)
	}
	if code, _ := s.do(t, "POST", "/mcp", initBody, "salah"); code != 401 {
		t.Fatalf("token salah: code=%d, mau 401", code)
	}

	// initialize -> serverInfo perisai-waf + protocolVersion.
	code, m := s.rpcCall(t, initBody, "tok-test")
	if code != 200 {
		t.Fatalf("initialize: code=%d body=%v", code, m)
	}
	res, _ := m["result"].(map[string]any)
	si, _ := res["serverInfo"].(map[string]any)
	if si["name"] != "perisai-waf" || res["protocolVersion"] != "2024-11-05" {
		t.Fatalf("initialize salah: %v", res)
	}

	// Notifikasi notifications/initialized -> 202 tanpa body.
	code, raw := s.do(t, "POST", "/mcp", map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	}, "tok-test")
	if code != 202 || len(raw) != 0 {
		t.Fatalf("notifikasi: code=%d body=%q, mau 202 kosong", code, raw)
	}

	// tools/list -> 7 tool termasuk get_stats.
	_, m = s.rpcCall(t, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
	}, "tok-test")
	res, _ = m["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) != 7 {
		t.Fatalf("jumlah tool = %d, mau 7: %v", len(tools), res)
	}
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"get_stats", "recent_requests", "list_rules",
		"toggle_rule", "list_sites", "list_ip_entries", "add_ip_entry"} {
		if !names[want] {
			t.Fatalf("tool %s tidak ada di daftar", want)
		}
	}

	// tools/call get_stats -> teks JSON memuat rules_loaded.
	_, m = s.rpcCall(t, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "get_stats", "arguments": map[string]any{}},
	}, "tok-test")
	stats := toolText(t, m)
	if _, ok := stats["rules_loaded"]; !ok {
		t.Fatalf("get_stats tanpa rules_loaded: %v", stats)
	}

	// tools/call add_ip_entry lalu list_ip_entries memuatnya.
	_, m = s.rpcCall(t, map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "add_ip_entry", "arguments": map[string]any{
			"ip": "203.0.113.7", "list": "black", "note": "uji mcp",
		}},
	}, "tok-test")
	added := toolText(t, m)
	if added["network"] != "203.0.113.7/32" || added["list"] != "black" {
		t.Fatalf("add_ip_entry: %v", added)
	}
	_, m = s.rpcCall(t, map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{"name": "list_ip_entries", "arguments": map[string]any{}},
	}, "tok-test")
	res, _ = m["result"].(map[string]any)
	content, _ := res["content"].([]any)
	text, _ := content[0].(map[string]any)["text"].(string)
	var entries []map[string]any
	if err := json.Unmarshal([]byte(text), &entries); err != nil || len(entries) != 1 {
		t.Fatalf("list_ip_entries: err=%v entries=%v", err, entries)
	}

	// Tool tidak dikenal -> error JSON-RPC.
	_, m = s.rpcCall(t, map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{"name": "tidak_ada", "arguments": map[string]any{}},
	}, "tok-test")
	if _, ok := m["error"]; !ok {
		t.Fatalf("tool asing harusnya error JSON-RPC: %v", m)
	}

	// Method tidak dikenal -> error -32601.
	_, m = s.rpcCall(t, map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "sumber/daya",
	}, "tok-test")
	errObj, _ := m["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Fatalf("method asing: %v", m)
	}
}
