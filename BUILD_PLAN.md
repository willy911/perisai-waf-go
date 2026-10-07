# BUILD PLAN — Port Perisai WAF Python → Go

Sumber kebenaran: `~/workspace/perisai-waf/` (Python). Target: repo ini
(`~/workspace/perisai-waf-go`), module `github.com/willy911/perisai-waf`.

Toolchain: `~/golang/bin/go` (Go 1.27.1). Selalu `export PATH=$HOME/golang/bin:$PATH`.
Deps (sudah di go.mod): `gopkg.in/yaml.v3`, `modernc.org/sqlite` (driver name `"sqlite"`),
`golang.org/x/crypto`. Boleh tambah dep pure-Go bila perlu (mis. maxminddb);
HINDARI cgo.

Sudah jadi (jangan ditulis ulang): `internal/config`, `internal/auth`.

## Konvensi
- Komentar Bahasa Indonesia (gaya repo asal). `gofmt` + `go vet` bersih.
- Port yang setia: perilaku, nama field JSON API, dan format harus sama dengan
  Python agar dashboard Svelte (`ui/`) tetap jalan tanpa perubahan.
- Setiap package: `*_test.go` dengan vektor uji dari `~/workspace/perisai-waf/tests/`.

## Kontrak package

### internal/rules
```go
type Hit struct{ RuleID, Name, Category, Severity, Evidence, Location string; Weight float64 }
type Request struct{ ID, Method, Path, Query string; Headers map[string]string; Body []byte; ClientIP string }
type TriageResult struct{ Score float64; Action string /* allow|agent|block */; Hits []Hit; Reasons []string }
type Rule struct{ ID, Name, Category, Severity string; Patterns []*regexp.Regexp; Weight float64 }
type Engine struct{ ... }
func NewEngine(cfg *config.WAFConfig, customRules []Rule) *Engine
func (e *Engine) Triage(r *Request) TriageResult
```
- 33 signature PERSIS dari `perisai/rules/signatures.py` (baca file-nya!): SQLI-001..007,
  XSS-001..008, RCE-001..006, LFI-001..003, SSRF-001, CVE-001..007, SCAN-001.
  Bobot: critical=40, high=25, medium=15, low=8.
- Python `re.compile(p, IGNORECASE|DOTALL)` → Go: `"(?is)" + p`. `\b` didukung RE2.
- Baca `perisai/engine.py`: zona pindai (path, query, body, header UA, dst),
  loop decode (mentah → url.QueryUnescape berulang maks 3x), evidence snippet,
  aksi dari `thresholds` (agent_score=25, block_score=60), alasan (reasons).
- Custom rules: pola regex dari storage (learner).

### internal/agent
```go
type Verdict struct{ Decision string; Confidence float64; Reasoning, Indicators []string; SuggestedRule map[string]any; Backend string; DurationMs float64 }
type Backend interface{ Name() string; Available() bool; Analyze(*rules.Request, rules.TriageResult) (Verdict, error) }
type Orchestrator struct{ ... }
func NewOrchestrator(cfg *config.WAFConfig, store *storage.Storage) *Orchestrator
func (o *Orchestrator) Analyze(r *rules.Request, t rules.TriageResult) (Verdict, error)
func (o *Orchestrator) TestLLM() map[string]any
func (o *Orchestrator) TestSystemOne() map[string]any
```
- Baca `perisai/agent/heuristic.py`, `llm.py`, `systemone.py`, `orchestrator.py`.
- Heuristic: port logika deteksi (evasion, multi-decode, dsb).
- LLM: POST `{base_url}/chat/completions` `{model, messages, temperature:0.1, max_tokens:800}`,
  system prompt SAMA PERSIS dari llm.py; parse JSON dari content; `FetchModels(baseURL, apiKey string) ([]map[string]string, error)` → GET `{base}/models`.
- SystemOne: POST `{endpoint}` body `{"model","state","questions"}`; pertanyaan
  `is_attack` type `noul` (instructions + criteria SAMA dari systemone.py);
  parse `answers.is_attack` → prefer `noul_raw` lalu `noul`; BLOCK_P=0.85;
  p≥0.85→block, p≥minConf→challenge, else allow(conf=1-p).
- Orchestrator: kandidat auto = systemone→llm→heuristic (skip bila tak available /
  cooldown 5 menit); mode eksplisit `llm|systemone|heuristic` + fallback heuristic;
  policy: hit critical ⇒ tak boleh allow; allow dengan confidence < min_confidence ⇒
  challenge; catat fallback di reasoning; `storage.LogAgentRun` tiap analisis.

### internal/storage
- `type Storage struct{ DB *sql.DB }`, `func New(dataDir string) (*Storage, error)`.
- DDL PERSIS dari `perisai/storage.py::_migrate` (baca file-nya sampai habis!).
- Method (tanda tangan Go-idiomatis, nama sama): LogRequest, RecentRequests,
  Stats, RequestCountsBySite, RecentBlockedIPs, LogAgentRun, RecentAgentRuns,
  ProposeRule, ListProposed, SetProposedStatus, ListSites, GetSite,
  GetSiteByDomain, UpsertSite, DeleteSite, ListIPEntries, UpsertIPEntry,
  DeleteIPEntry, GetSetting, SetSetting, CreateIPGroup, ListIPGroups,
  GetIPGroup, UpdateIPGroup, DeleteIPGroup, AddGroupMember, RemoveGroupMember,
  GeoGet, GeoSet, GetIP, UpsertIP, ListCustomRules.
- Driver: `_ "modernc.org/sqlite"`, open `"sqlite"`, path `dataDir/perisai.db`.

### internal/ratelimit — `New(rps float64, burst int) *Limiter`, `Allow(key string) bool` (token bucket + mutex).
### internal/reputation — `New(cfg config.ReputationConfig, store *storage.Storage)`; `Check(ip string) (blocked bool)`; pakai storage.GetIP/UpsertIP (strikes, window, block).
### internal/iplists — `New(store *storage.Storage)`; `IsWhitelisted(ip)`, `IsBlacklisted(ip)` (CIDR, entries + groups); `Invalidate()`.
### internal/learner — `MaybeLearn(store, verdict, triage)`: bila learning.enabled dan suggested_rule ada dan confidence ≥ min → ProposeRule; bila auto_approve → aktifkan sebagai custom rule.
### internal/uploadscan — `Scan(filename string, content []byte, cfg config.UploadScanConfig) (blocked bool, reason string)`: ekstensi diblokir, double-extension, magic bytes, signature webshell (baca `perisai/uploadscan.py`), EICAR.
### internal/cache — cache WAF-side per site: `New()`, `Get/Put` dengan TTL, max entries, max object KB, bypass bila cookie sesi cocok.
### internal/recaptcha — `Verify(secret, token, remoteIP, minScore) (ok bool, err error)` v2/v3 via googleapis.
### internal/tlscerts — `ParseExpiry(certPEM)`, `Domains(certPEM)`, validasi pasangan cert/key.
### internal/geo — `Lookup(ip) (country, city, lat, lon)`: provider mmdb (dep pure-Go, file di data_dir bila ada) → api (ip-api.com) → off; cache via storage.GeoGet/GeoSet.
### internal/cloudflare — client API: `VerifyToken`, `ListZones`, `ZoneStats`, `PurgeCache`; konstanta IP range resmi Cloudflare (dari config.example.yaml Python).

### internal/proxy
```go
type Server struct{ ... }
func NewServer(cfg *config.WAFConfig, eng *rules.Engine, orch *agent.Orchestrator, store *storage.Storage, ...) *Server
func (s *Server) Handler() http.Handler
func (s *Server) ListenAndServe() error  // HTTP; TLS opsional via cfg.TLS + SNI per-site
```
- Baca `perisai/proxy.py` + `perisai/waf.py` sampai paham alurnya!
- IP asli: bila peer ∈ trusted_proxies → CF-Connecting-IP lalu X-Forwarded-For.
- Per request: site by Host → iplists (white bypass semua, black → 403) → reputation
  → ratelimit (429) → ddos_mode: challenge-first + limit ketat → baca body (max_body_mb)
  → upload scan (multipart) → engine.Triage → block→403 / agent→orchestrator →
  challenge→JS-cookie (set cookie `perisai_chal`, verifikasi, ulangi request) atau
  reCAPTCHA bila site.recaptcha_enabled → allow→reverse proxy
  (`httputil.ReverseProxy`, preserve Host, upstream TLS opsional, X-Forwarded-*).
- Challenge cookie: HMAC-SHA256(ip+ua+secret harian), redirect loop aman.
- Catat tiap request ke storage (LogRequest) + durasi.

### internal/dashboard
- Baca `perisai/dashboard.py` (900+ baris) DAN `docs/UI-API-CONTRACT.md` DAN
  `ui/src/lib/types.ts` — bentuk JSON harus PERSIS agar SPA jalan.
- Auth: session cookie/token 12 jam (`auth.SessionStore`) + token statis
  `?token=`/`Authorization: Bearer`; `POST /api/login`, `/api/logout`;
  LoginThrottle (5 gagal → kunci 5 menit).
- Endpoint (GET/POST/PUT/DELETE): /api/stats, /api/requests, /api/agent-runs,
  /api/proposed + /{id}/approve|/reject, /api/agent/test, /api/systemone/test,
  /api/attack-map, /api/iplists, /api/ip-groups..., /api/sites... (+/ddos, /cert),
  /api/rules + /{id}/toggle, /api/ai-config, /api/ai-models, /api/systemone-config,
  /api/cache/*, /api/recaptcha/config, /api/cf/*, /api/login, /api/logout.
- Serve SPA: `ui/dist` (embed via `embed.FS`), fallback `index.html` untuk route SPA.
- API key/token tak pernah dikirim utuh (`api_key_set` saja).

### cmd/perisai — main.go: load config → storage → engine(+custom rules) → orchestrator →
  proxy server → dashboard server; graceful shutdown (SIGINT/SIGTERM).
### cmd/setpassword — CLI atur username+password dashboard (baca perisai/setpassword.py).

## Urutan kerja (paralel bila independen)
1. rules, storage, ratelimit, reputation, iplists, learner, uploadscan, cache (independen)
2. agent (butuh rules + storage + config)
3. proxy, dashboard (butuh semua), geo/cloudflare/tlscerts/recaptcha (independen, bisa gabung batch 1)
4. cmd/*, config.example.yaml, install.sh, Dockerfile, README, copy `ui/`
5. `go build ./...`, `go vet ./...`, `go test ./...` HIJAU. Smoke test: jalanin server,
   login, hit API.

## Kriteria selesai fase 1
- Build + vet + test hijau. Dashboard serve SPA; login + semua endpoint utama
  diverifikasi via smoke test nyata (bukan cuma unit test).
