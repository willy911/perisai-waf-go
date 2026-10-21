package mcp

// Test dasar dispatcher JSON-RPC: initialize, ping, parse error, dan
// hasil isError dari handler tool.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testDispatcher() *Dispatcher {
	return NewDispatcher([]Tool{{
		Name:        "echo",
		Description: "gema",
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			if args["gagal"] == true {
				return nil, errors.New("disuruh gagal")
			}
			return map[string]any{"args": args}, nil
		},
	}})
}

func post(t *testing.T, d *Dispatcher, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestDispatcher(t *testing.T) {
	d := testDispatcher()

	code, body := post(t, d, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if code != 200 || !strings.Contains(body, `"perisai-waf"`) ||
		!strings.Contains(body, `"2024-11-05"`) {
		t.Fatalf("initialize: code=%d body=%s", code, body)
	}

	code, body = post(t, d, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if code != http.StatusAccepted || body != "" {
		t.Fatalf("notifikasi: code=%d body=%q", code, body)
	}

	code, body = post(t, d, `{"jsonrpc":"2.0","id":2,"method":"tools/call",`+
		`"params":{"name":"echo","arguments":{"a":1}}}`)
	if code != 200 || !strings.Contains(body, `"text"`) ||
		strings.Contains(body, `"isError":true`) {
		t.Fatalf("tools/call: code=%d body=%s", code, body)
	}

	// Error handler -> hasil isError, bukan error JSON-RPC.
	_, body = post(t, d, `{"jsonrpc":"2.0","id":3,"method":"tools/call",`+
		`"params":{"name":"echo","arguments":{"gagal":true}}}`)
	if !strings.Contains(body, `"isError":true`) ||
		!strings.Contains(body, "disuruh gagal") {
		t.Fatalf("isError: body=%s", body)
	}

	// JSON rusak -> parse error -32700.
	_, body = post(t, d, `{bukan json`)
	if !strings.Contains(body, "-32700") {
		t.Fatalf("parse error: body=%s", body)
	}
}
