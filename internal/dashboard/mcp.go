package dashboard

// Server MCP (Model Context Protocol) di endpoint POST /mcp — fitur
// SafeLine "mcp_server". Dispatcher JSON-RPC ada di package
// internal/mcp; tool konkret di sini memakai store/engine dashboard
// yang sudah ada. Auth memakai token dashboard yang sama seperti /api
// (route dibungkus guard requireAuth di Handler()).

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/willy911/perisai-waf/internal/mcp"
)

// handleMCP: POST /mcp — endpoint MCP (JSON-RPC 2.0).
func (d *Dashboard) handleMCP(w http.ResponseWriter, r *http.Request) {
	d.mcpDispatcher().ServeHTTP(w, r)
}

// schemaObj membuat JSON-schema objek sederhana untuk input tool.
func schemaObj(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// strArg mengambil argumen string dari peta argumen tool.
func strArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// mcpDispatcher membangun dispatcher MCP dengan tool-tool Perisai.
func (d *Dashboard) mcpDispatcher() *mcp.Dispatcher {
	return mcp.NewDispatcher([]mcp.Tool{
		{
			Name:        "get_stats",
			Description: "Statistik trafik & serangan 24 jam terakhir (termasuk rules_loaded).",
			InputSchema: schemaObj(nil),
			Handler: func(_ context.Context, _ map[string]any) (any, error) {
				st, err := d.store.Stats(nowSec() - 86400)
				if err != nil {
					return nil, err
				}
				st["rules_loaded"] = len(d.eng.Rules())
				return st, nil
			},
		},
		{
			Name:        "recent_requests",
			Description: "Log request terbaru (termasuk keputusan WAF & rule pemicu).",
			InputSchema: schemaObj(map[string]any{
				"limit": map[string]any{
					"type":        "integer",
					"description": "Jumlah baris (default 20, maks 500).",
				},
			}),
			Handler: func(_ context.Context, args map[string]any) (any, error) {
				limit := 20
				if v, ok := args["limit"].(float64); ok && v > 0 {
					limit = int(v)
				}
				if limit > 500 {
					limit = 500
				}
				rows, err := d.store.RecentRequests(limit, "")
				if err != nil {
					return nil, err
				}
				if rows == nil {
					rows = []map[string]any{}
				}
				return rows, nil
			},
		},
		{
			Name:        "list_rules",
			Description: "Daftar signature WAF beserta status aktif/nonaktif-nya.",
			InputSchema: schemaObj(nil),
			Handler: func(_ context.Context, _ map[string]any) (any, error) {
				out := make([]map[string]any, 0)
				for _, rule := range d.eng.Rules() {
					out = append(out, map[string]any{
						"id": rule.ID, "name": rule.Name,
						"category": rule.Category, "severity": rule.Severity,
						"weight": rule.Weight, "disabled": d.isDisabled(rule.ID),
					})
				}
				return out, nil
			},
		},
		{
			Name:        "toggle_rule",
			Description: "Menyalakan/mematikan satu signature secara global.",
			InputSchema: schemaObj(map[string]any{
				"id":      map[string]any{"type": "string"},
				"enabled": map[string]any{"type": "boolean"},
			}, "id", "enabled"),
			Handler: func(_ context.Context, args map[string]any) (any, error) {
				id := strArg(args, "id")
				if id == "" {
					return nil, errors.New("argumen id wajib diisi")
				}
				enabled, ok := args["enabled"].(bool)
				if !ok {
					return nil, errors.New("argumen enabled (boolean) wajib diisi")
				}
				if !d.setRuleDisabled(id, !enabled) {
					return nil, errors.New("rule tidak dikenal: " + id)
				}
				return map[string]any{
					"id": id, "enabled": enabled, "disabled": !enabled,
				}, nil
			},
		},
		{
			Name:        "list_sites",
			Description: "Daftar website yang dilindungi (hash auth tidak pernah disertakan).",
			InputSchema: schemaObj(nil),
			Handler: func(_ context.Context, _ map[string]any) (any, error) {
				sites, err := d.store.ListSites()
				if err != nil {
					return nil, err
				}
				if sites == nil {
					sites = []map[string]any{}
				}
				for _, s := range sites {
					siteView(s)
				}
				return sites, nil
			},
		},
		{
			Name:        "list_ip_entries",
			Description: "Daftar entri whitelist/blacklist IP (global & per-site).",
			InputSchema: schemaObj(nil),
			Handler: func(_ context.Context, _ map[string]any) (any, error) {
				rows, err := d.store.ListIPEntries()
				if err != nil {
					return nil, err
				}
				if rows == nil {
					rows = []map[string]any{}
				}
				return rows, nil
			},
		},
		{
			Name:        "add_ip_entry",
			Description: "Tambah IP/CIDR ke whitelist (white) atau blacklist (black) global.",
			InputSchema: schemaObj(map[string]any{
				"ip":   map[string]any{"type": "string"},
				"list": map[string]any{"type": "string", "enum": []string{"white", "black"}},
				"note": map[string]any{"type": "string"},
			}, "ip", "list"),
			Handler: func(_ context.Context, args map[string]any) (any, error) {
				network := strings.TrimSpace(strArg(args, "ip"))
				lst := strings.TrimSpace(strArg(args, "list"))
				if network == "" || (lst != "white" && lst != "black") {
					return nil, errors.New("ip & list=white|black wajib diisi")
				}
				normalized, ok := normalizeNetwork(network)
				if !ok {
					return nil, errors.New("format IP/CIDR tidak valid")
				}
				eid, err := randomID12()
				if err != nil {
					return nil, err
				}
				entry := map[string]any{
					"id": eid, "network": normalized, "list": lst,
					"scope": "global",
					"note":  strings.TrimSpace(strArg(args, "note")),
				}
				if err := d.store.UpsertIPEntry(entry); err != nil {
					return nil, err
				}
				d.ipl.Invalidate()
				return map[string]any{
					"id": eid, "network": normalized, "list": lst,
				}, nil
			},
		},
	})
}
