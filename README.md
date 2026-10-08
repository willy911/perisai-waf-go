# Perisai WAF — port Go dari implementasi Python.
#
# Arsitektur 3 lapis (sama seperti versi Python):
#  1. Rules engine: 34 signature (SQLi/XSS/RCE/LFI/SSRF/CVE/scanner) + triase skor
#     (allow <25, agent 25-59, block >=60), pindai zona mentah + ter-decode.
#  2. AI agent untuk trafik abu-abu: backend heuristic, LLM OpenAI-compatible,
#     atau System One (/v1/systemone, non-autoregresif); mode auto dengan
#     fallback + cooldown 5 menit; batas kebijakan: hit kritis tak boleh
#     di-allow, confidence rendah -> challenge.
#  3. Adaptif: reputasi IP, rate limit token bucket, auto-learning.
#
# Fitur: reverse proxy HTTP(S) + terminasi TLS/SNI per-site, challenge JS-cookie,
# reCAPTCHA v2/v3, multi-site, Mode Serangan DDoS per-domain, cache WAF-side,
# whitelist/blacklist CIDR + grup IP, scan upload malware, peta serangan GeoIP,
# integrasi Cloudflare, dashboard admin (Svelte, serve dari ui/dist).
#
# Hasil port oleh koordinator + 11 worker subagent (2026-10-07).

## Instalasi

### Opsi 1: Docker

Tarik image:

```sh
docker pull willy911/perisai-waf:latest
```

Jalankan container:

```sh
mkdir -p perisai-data
docker run -d \
  --name perisai-waf \
  -p 8080:8080 \
  -p 8899:8899 \
  -v perisai-data:/app/data \
  -e DATA_DIR=/app/data \
  -e PORT=8080 \
  -e DASHBOARD_PORT=8899 \
  -e HOSTNAME=0.0.0.0 \
  -e INITIAL_USER=admin \
  -e INITIAL_PASSWORD=<password-dashboard-anda> \
  -e DASHBOARD_TOKEN=<generate-dengan-openssl-rand-hex-32> \
  willy911/perisai-waf:latest
```

Dashboard terbuka di http://localhost:8899 — login dengan `INITIAL_USER` /
`INITIAL_PASSWORD` di atas. (Password hanya dipakai sekali saat pertama kali;
setelah tersimpan, mengubah env tidak akan menimpa password yang sudah ada.)

Build image sendiri:

```sh
docker build -t willy911/perisai-waf:latest .
```

### Opsi 2: Docker Compose

File `docker-compose.yml` sudah termasuk di repo ini:

```sh
cp .env.example .env   # isi INITIAL_PASSWORD (dan DASHBOARD_TOKEN bila perlu)
docker compose up -d
```

Dashboard terbuka di http://localhost:8899 (atau sesuai `DASHBOARD_PORT` di `.env`).

### Opsi 3: Binary langsung

Lihat [Menjalankan](#menjalankan) di bawah.

## Menjalankan

```sh
# 1. Build (butuh Go >= 1.24; tanpa cgo)
export PATH=$HOME/golang/bin:$PATH
go build -o perisai ./cmd/perisai
go build -o perisai-setpassword ./cmd/setpassword

# 2. Build dashboard UI (butuh Node >= 20)
cd ui && npm ci && npm run build && cd ..

# 3. Siapkan config
cp config.example.yaml config.yaml
# edit config.yaml: token dashboard, upstream, dsb.

# 4. Atur login dashboard
./perisai-setpassword --config config.yaml

# 5. Jalankan
./perisai --config config.yaml
# proxy  -> :8080 (atau sesuai config)
# dashboard -> 127.0.0.1:8899
```

Atau via Docker:

```sh
docker build -t perisai-waf .
docker run -d --name perisai -p 8080:8080 -p 8899:8899 \
  -v $PWD/config.yaml:/app/config.yaml -v $PWD/data:/app/data perisai-waf
```

## Struktur

```
cmd/perisai        binary utama (proxy + dashboard)
cmd/setpassword    CLI atur login dashboard
internal/
  config           YAML + env + fungsi save
  auth             hash PBKDF2, session 12 jam, anti brute-force
  rules            34 signature + triase
  agent            heuristic / llm / systemone + orkestrator
  storage          SQLite (modernc.org/sqlite, pure Go)
  proxy            reverse proxy + pipeline pertahanan
  dashboard        API admin + serve SPA
  ratelimit        token bucket per IP
  reputation       strike IP
  iplists          whitelist/blacklist CIDR + grup
  learner          auto-learning signature
  uploadscan       scan malware upload
  cache            cache WAF-side per site
  geo              GeoIP (mmdb/api/off)
  cloudflare       API Cloudflare + IP range resmi
  tlscerts         util sertifikat
  recaptcha        verifikasi reCAPTCHA v2/v3
ui/                dashboard Svelte (dipakai ulang dari versi Python, tanpa perubahan)
```

## Menu Terminal (dashboard)

Shell interaktif langsung di server WAF via websocket — untuk menjalankan
perintah di folder aplikasi tanpa SSH. Direktori kerja terminal = direktori
kerja proses saat start (di Docker: `/app`, yaitu folder perisai-waf).

- Backend: `internal/terminal` (PTY via `creack/pty`) + endpoint
  `GET /api/terminal/ws` di `internal/dashboard` (wajib login; tanpa token → 401).
- Endpoint `GET /api/terminal/config` → `{enabled, shell, work_dir}`.
- UI: `ui/src/routes/Terminal.svelte` (xterm.js) + menu "Terminal" di sidebar.
- Semua baris perintah dicatat ke log server (`[terminal] $ ...`) untuk audit.
- Konfigurasi (`config.yaml`):
  ```yaml
  terminal:
    enabled: true
    shell: "bash"   # fallback otomatis ke "sh"
    work_dir: ""    # kosong = direktori kerja proses (di Docker: /app)
  ```
- Image Docker menyertakan `bash` agar terminal penuh di dalam container.

## Catatan port

- Bentuk JSON API dashboard PERSIS seperti versi Python agar SPA lama jalan
  tanpa perubahan.
- Penyimpangan yang disengaja dari Python didokumentasikan di laporan akhir
  (challenge 302+Set-Cookie server-side, double-extension lebih ketat, dsb).
- `go build ./...`, `go vet ./...`, `go test ./...` hijau (207 test).
