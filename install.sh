#!/usr/bin/env bash
# Install Perisai WAF (Go) — one-command setup.
# Jalankan dari folder repo ini.
set -euo pipefail

GO_BIN="${GO_BIN:-$HOME/golang/bin/go}"
if ! "$GO_BIN" version >/dev/null 2>&1; then
  echo "Go tidak ditemukan di $GO_BIN."
  echo "Install Go >= 1.24 dulu (https://go.dev/dl/), lalu ulangi."
  exit 1
fi

echo "==> build..."
export PATH="$(dirname "$GO_BIN"):$PATH"
go build -o perisai ./cmd/perisai
go build -o perisai-setpassword ./cmd/setpassword

echo "==> siapkan config & data..."
[ -f config.yaml ] || cp config.example.yaml config.yaml
mkdir -p data

if ! grep -q 'password_hash: "[^"]' config.yaml 2>/dev/null; then
  echo "==> atur login dashboard:"
  ./perisai-setpassword --config config.yaml
fi

echo ""
echo "Selesai. Jalankan:  ./perisai --config config.yaml"
echo "Dashboard: http://127.0.0.1:8899  (lihat port di config.yaml)"
