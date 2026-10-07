# Dashboard Perisai WAF (Svelte)

Frontend dashboard Perisai WAF — **Svelte 5 + TypeScript + Tailwind CSS v4 +
shadcn-svelte + bits-ui**, dibuild dengan Vite.

## Prasyarat

- Node.js ≥ 20, npm ≥ 10
- Backend Perisai WAF berjalan (default `http://127.0.0.1:8899`)

## Development

```bash
cd ui
npm install
npm run dev      # http://127.0.0.1:5173 — /api & /map-land.json di-proxy ke :8899
```

Login memakai username+password yang sama dengan dashboard lama
(token disimpan di `localStorage`, sesi 12 jam).

## Build produksi

```bash
cd ui
npm run build    # output ke ui/dist/
npm run check    # type-check (svelte-check), harus 0 error
```

Hasil build (`ui/dist/`) **dikomit ke repo** — server dashboard Python
menyajikannya sebagai pengganti `perisai/ui/index.html` lama. Deployment di
VPS tetap tanpa Node.js.

> Catatan: `perisai/ui/index.html` (dashboard vanilla lama) tetap ada sebagai
> fallback sampai backend dialihkan menyajikan `ui/dist/`.

## Struktur

```
ui/
  src/
    main.ts            # entry point
    App.svelte         # layout sidebar + hash-router + login gate
    app.css            # tema gelap (Tailwind v4 @theme)
    lib/
      api.ts           # fetch wrapper (?token= otomatis, 401 -> login)
      types.ts         # bentuk data API (lihat docs/UI-API-CONTRACT.md)
      stores.ts        # route, auth, toast
      utils.ts         # cn(), format tanggal/bytes
      components/
        ui/            # komponen shadcn-svelte (button, card, dialog, ...)
        AttackMap.svelte
        TrendChart.svelte
    routes/            # 9 halaman sidebar + Login
      Dashboard.svelte   # statistik, panel Cloudflare, tren, peta, penalaran AI
      Website.svelte     # CRUD site, DDoS toggle, SSL, mapping zone CF
      Logs.svelte        # interceptions logs + filter
      IpList.svelte      # black/whitelist IP
      Rules.svelte       # usulan aturan + signature
      Recaptcha.svelte   # config reCAPTCHA global + per site
      Cache.svelte       # config & statistik cache WAF per site
      IpGroup.svelte     # grup IP/CIDR
      Settings.svelte    # Setting AI + sesi
      Login.svelte
```

## Kontrak API

Bentuk request/response tiap endpoint mengikuti
[`docs/UI-API-CONTRACT.md`](../docs/UI-API-CONTRACT.md). Untuk endpoint
**baru** (cache, ip-group, recaptcha, cloudflare) yang backend-nya belum ada,
UI sudah sesuai kontrak — halaman menampilkan pesan error backend apa adanya
bila endpoint belum tersedia.
