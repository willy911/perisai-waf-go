// Package mcp mengimplementasikan server MCP (Model Context Protocol)
// minimal di atas JSON-RPC 2.0 transport HTTP: initialize, ping,
// tools/list, dan tools/call.
//
// Package ini sengaja hanya tahu tipe Tool & Dispatcher — implementasi
// tool konkret dibuat pemakai (dashboard) memakai storage/engine-nya
// sendiri, agar tidak ada siklus impor.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Tool adalah satu kemampuan yang diekspos ke klien MCP.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, args map[string]any) (any, error)
}

// Dispatcher melayani request JSON-RPC 2.0 untuk sekumpulan Tool.
type Dispatcher struct {
	tools  []Tool
	byName map[string]*Tool
}

// NewDispatcher membuat Dispatcher dari daftar tool.
func NewDispatcher(tools []Tool) *Dispatcher {
	d := &Dispatcher{byName: map[string]*Tool{}}
	for i := range tools {
		d.tools = append(d.tools, tools[i])
		d.byName[tools[i].Name] = &d.tools[len(d.tools)-1]
	}
	return d
}

// Tools mengembalikan daftar tool terdaftar.
func (d *Dispatcher) Tools() []Tool { return d.tools }

// -- JSON-RPC 2.0 ------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, rerr *rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(rpcResponse{
		JSONRPC: "2.0", ID: id, Result: result, Error: rerr,
	})
}

// ServeHTTP melayani satu request JSON-RPC (POST). Notifikasi (tanpa
// id) tidak dibalas: 202 tanpa body, sesuai spesifikasi MCP.
func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}
	var req rpcRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&req); err != nil {
		writeRPC(w, nil, nil, &rpcError{Code: -32700, Message: "parse error"})
		return
	}
	if len(req.ID) == 0 {
		// Notifikasi (mis. notifications/initialized) -> 202 tanpa body.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	result, rerr := d.dispatch(r.Context(), req)
	writeRPC(w, req.ID, result, rerr)
}

func (d *Dispatcher) dispatch(ctx context.Context, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "perisai-waf", "version": "1.0.0"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		out := make([]map[string]any, 0, len(d.tools))
		for _, t := range d.tools {
			schema := t.InputSchema
			if schema == nil {
				schema = map[string]any{
					"type": "object", "properties": map[string]any{},
				}
			}
			out = append(out, map[string]any{
				"name": t.Name, "description": t.Description,
				"inputSchema": schema,
			})
		}
		return map[string]any{"tools": out}, nil
	case "tools/call":
		return d.callTool(ctx, req.Params)
	default:
		return nil, &rpcError{
			Code: -32601, Message: "method tidak ditemukan: " + req.Method,
		}
	}
}

// callTool menjalankan satu tool. Error dari handler dilaporkan sebagai
// hasil MCP isError (bukan error JSON-RPC), sesuai konvensi MCP.
func (d *Dispatcher) callTool(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &rpcError{Code: -32602, Message: "params tidak valid"}
	}
	tool, ok := d.byName[params.Name]
	if !ok {
		return nil, &rpcError{
			Code: -32602, Message: "tool tidak dikenal: " + params.Name,
		}
	}
	args := map[string]any{}
	if len(params.Arguments) > 0 {
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return nil, &rpcError{
				Code: -32602, Message: "arguments harus objek JSON",
			}
		}
	}
	res, err := tool.Handler(ctx, args)
	if err != nil {
		return toolErrorResult(err), nil
	}
	text, merr := json.Marshal(res)
	if merr != nil {
		return toolErrorResult(
			fmt.Errorf("hasil tool tidak bisa di-JSON: %w", merr)), nil
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
	}, nil
}

// toolErrorResult membungkus error handler sebagai hasil MCP isError.
func toolErrorResult(err error) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": err.Error()}},
		"isError": true,
	}
}
