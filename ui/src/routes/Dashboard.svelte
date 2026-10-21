<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtTime, fmtBytes } from "$lib/utils.js";
	import type {
		StatsResponse,
		WafRequest,
		AgentRun,
		CfConfig,
		CfStats,
		Site,
		AttackPoint,
	} from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import {
		Table,
		TableHeader,
		TableBody,
		TableRow,
		TableHead,
		TableCell,
	} from "$lib/components/ui/table/index.js";
	import AttackMap from "$lib/components/AttackMap.svelte";
	import TrendChart from "$lib/components/TrendChart.svelte";
	import { CloudOff, KeyRound } from "lucide-svelte";

	let stats = $state<StatsResponse | null>(null);
	let requests = $state<WafRequest[]>([]);
	let agentRuns = $state<AgentRun[]>([]);
	let cfConfig = $state<CfConfig | null>(null);
	let cfStats = $state<CfStats | null>(null);
	let cfStatsErr = $state("");
	let sites = $state<Site[]>([]);
	let attackPoints = $state<AttackPoint[]>([]);
	let cfSiteId = $state("");
	let cfToken = $state("");
	let cfSaving = $state(false);

	async function load() {
		try {
			const [s, r, a] = await Promise.all([
				apiGet<StatsResponse>("/api/stats"),
				apiGet<WafRequest[]>("/api/requests?limit=500"),
				apiGet<AgentRun[]>("/api/agent-runs?limit=10"),
			]);
			stats = s;
			requests = r;
			agentRuns = a;
		} catch (e) {
			toast("Gagal memuat statistik", { variant: "destructive" });
		}
		try {
			attackPoints = await apiGet<AttackPoint[]>("/api/attack-map?hours=24");
		} catch {
			attackPoints = [];
		}
		try {
			const [cfg, st] = await Promise.all([
				apiGet<CfConfig>("/api/cf/config"),
				apiGet<Site[]>("/api/sites"),
			]);
			cfConfig = cfg;
			sites = st;
			if (cfg.api_token_set && !cfSiteId) {
				cfSiteId = cfg.zones[0]?.site_id ?? "";
				if (cfSiteId) loadCfStats();
			}
		} catch {
			// endpoint CF mungkin belum ada di backend — tampilkan placeholder
			cfConfig = null;
		}
	}

	async function loadCfStats() {
		cfStatsErr = "";
		cfStats = null;
		if (!cfSiteId) return;
		try {
			cfStats = await apiGet<CfStats>(`/api/cf/stats?site_id=${encodeURIComponent(cfSiteId)}`);
		} catch (e) {
			cfStatsErr = e instanceof Error ? e.message : "Gagal memuat statistik Cloudflare.";
		}
	}

	async function saveCfToken() {
		if (!cfToken.trim()) {
			toast("API token Cloudflare wajib diisi", { variant: "destructive" });
			return;
		}
		cfSaving = true;
		try {
			await apiPost("/api/cf/config", { api_token: cfToken.trim() });
			cfToken = "";
			toast("Token Cloudflare tersimpan");
			const cfg = await apiGet<CfConfig>("/api/cf/config");
			cfConfig = cfg;
		} catch (e) {
			toast("Gagal menyimpan token", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		} finally {
			cfSaving = false;
		}
	}

	function decisionBadge(d: string): "success" | "warning" | "destructive" | "secondary" {
		if (d === "allow") return "success";
		if (d === "challenge" || d === "cache_hit") return "warning";
		if (d === "block" || d === "rate_limited") return "destructive";
		return "secondary";
	}

	onMount(() => {
		load();
		const t = setInterval(load, 15000);
		return () => clearInterval(t);
	});

	let d = $derived(stats?.by_decision ?? {});

	// Angka ringkas ala SafeLine (27.0k).
	const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
	function fmtK(n: number | undefined): string {
		return n === undefined ? "…" : compact.format(n);
	}

	let uniqIPs = $derived(new Set(requests.map((r) => r.ip)).size);
	let countries = $derived.by(() => {
		const byCountry = new Map<string, number>();
		for (const p of attackPoints) {
			byCountry.set(p.country || "?", (byCountry.get(p.country || "?") ?? 0) + p.count);
		}
		return [...byCountry.entries()]
			.map(([country, count]) => ({ country, count }))
			.sort((a, b) => b.count - a.count)
			.slice(0, 8);
	});
	let countryMax = $derived(Math.max(1, ...countries.map((c) => c.count)));
</script>

<div class="space-y-6">
	<div class="flex flex-wrap items-end justify-between gap-3">
		<div>
			<h1 class="text-2xl font-extrabold tracking-tight">Dashboard</h1>
			<p class="text-sm text-muted-foreground">Ringkasan proteksi 24 jam terakhir</p>
		</div>
		<div class="flex items-center gap-2">
			<span class="rounded-lg bg-primary px-3.5 py-1.5 text-xs font-bold text-primary-foreground shadow-md shadow-primary/25">24 JAM</span>
			<span class="cursor-not-allowed rounded-lg bg-card px-3.5 py-1.5 text-xs font-bold text-muted-foreground opacity-60 shadow-sm" title="Belum tersedia">7 HARI</span>
			<span class="cursor-not-allowed rounded-lg bg-card px-3.5 py-1.5 text-xs font-bold text-muted-foreground opacity-60 shadow-sm" title="Belum tersedia">30 HARI</span>
		</div>
	</div>

	<!-- kartu statistik berkelompok ala SafeLine -->
	<div class="grid gap-4 lg:grid-cols-3">
		<Card>
			<CardContent class="grid grid-cols-3 divide-x divide-border px-2 py-5">
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-primary"></span>Total Request</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(stats?.total)}</div>
				</div>
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-emerald-500"></span>Allow</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(d.allow)}</div>
				</div>
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-sky-500"></span>IP Unik</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(uniqIPs)}</div>
				</div>
			</CardContent>
		</Card>
		<Card>
			<CardContent class="grid grid-cols-3 divide-x divide-border px-2 py-5">
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-rose-500"></span>Block</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(d.block)}</div>
				</div>
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-amber-500"></span>Challenge</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(d.challenge)}</div>
				</div>
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-orange-500"></span>Rate Limited</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(d.rate_limited)}</div>
				</div>
			</CardContent>
		</Card>
		<Card>
			<CardContent class="grid grid-cols-3 divide-x divide-border px-2 py-5">
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-violet-500"></span>Signature Aktif</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(stats?.rules_loaded)}</div>
				</div>
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-teal-500"></span>Cache Hit</div>
					<div class="mt-1.5 text-[26px] font-extrabold leading-none">{fmtK(d.cache_hit)}</div>
				</div>
				<div class="px-4">
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground"><span class="size-2 rounded-full bg-red-500"></span>Top Offender</div>
					<div class="mt-1.5 truncate text-[15px] font-extrabold leading-none" title={stats?.top_offenders?.[0]?.ip ?? ""}>
						{stats?.top_offenders?.[0] ? `${stats.top_offenders[0].count}x` : "—"}
					</div>
					<div class="mt-1 truncate text-[11px] text-muted-foreground">{stats?.top_offenders?.[0]?.ip ?? "belum ada"}</div>
				</div>
			</CardContent>
		</Card>
	</div>

	<!-- panel Cloudflare -->
	<Card>
		<CardHeader>
			<CardTitle>☁️ Statistik Cloudflare</CardTitle>
			<CardDescription>Di-proxy server-side — token tidak pernah ke browser</CardDescription>
		</CardHeader>
		<CardContent>
			{#if cfConfig === null}
				<div class="flex items-center gap-3 text-sm text-muted-foreground">
					<CloudOff class="size-5" />
					<span>Integrasi Cloudflare belum tersedia di backend.</span>
				</div>
			{:else if !cfConfig.api_token_set}
				<div class="max-w-md space-y-3">
					<p class="text-sm text-muted-foreground">
						Belum terhubung. Buat API token di dashboard Cloudflare (permission:
						<code class="rounded bg-input px-1">Zone / Zone / Read</code>,
						<code class="rounded bg-input px-1">Zone / Analytics / Read</code>,
						<code class="rounded bg-input px-1">Zone / Cache Purge / Purge</code>),
						lalu tempel di bawah.
					</p>
					<div class="space-y-2">
						<Label for="cf-token">API Token</Label>
						<Input id="cf-token" type="password" bind:value={cfToken} placeholder="tempel token…" autocomplete="off" />
					</div>
					<Button onclick={saveCfToken} disabled={cfSaving}>
						<KeyRound class="size-4" />
						{cfSaving ? "Menyimpan…" : "Hubungkan"}
					</Button>
				</div>
			{:else}
				<div class="space-y-4">
					<div class="flex flex-wrap items-center gap-3">
						<Label for="cf-site">Website</Label>
						<select
							id="cf-site"
							class="h-9 rounded-md border border-input bg-input px-3 text-sm"
							bind:value={cfSiteId}
							onchange={loadCfStats}
						>
							{#each cfConfig.zones as z (z.site_id)}
								<option value={z.site_id}>{z.zone_name || z.site_id}</option>
							{/each}
						</select>
						{#if !cfConfig.zones.length}
							<span class="text-sm text-muted-foreground">
								Belum ada mapping zone — atur di halaman Website.
							</span>
						{/if}
					</div>
					{#if cfStatsErr}
						<p class="text-sm text-destructive">{cfStatsErr}</p>
					{:else if cfStats}
						<div class="grid grid-cols-2 gap-4 md:grid-cols-4">
							<div><div class="text-2xl font-bold">{cfStats.requests.toLocaleString("id-ID")}</div><div class="text-xs text-muted-foreground">Request</div></div>
							<div><div class="text-2xl font-bold text-rose-500">{cfStats.threats.toLocaleString("id-ID")}</div><div class="text-xs text-muted-foreground">Threats</div></div>
							<div><div class="text-2xl font-bold text-emerald-600">{cfStats.cached_pct}%</div><div class="text-xs text-muted-foreground">Cached</div></div>
							<div><div class="text-2xl font-bold">{fmtBytes(cfStats.bandwidth)}</div><div class="text-xs text-muted-foreground">Bandwidth</div></div>
						</div>
						<p class="text-xs text-muted-foreground">Diperbarui: {fmtTime(cfStats.updated_at)}</p>
					{:else if cfSiteId}
						<p class="text-sm text-muted-foreground">Memuat…</p>
					{/if}
				</div>
			{/if}
		</CardContent>
	</Card>

	<div class="grid items-start gap-4 lg:grid-cols-3">
		<div class="lg:col-span-2">
			<TrendChart {requests} />
		</div>
		<Card>
			<CardHeader>
				<CardTitle>Negara Asal Serangan</CardTitle>
				<CardDescription>Serangan terblokir per negara (24 jam)</CardDescription>
			</CardHeader>
			<CardContent class="space-y-3.5">
				{#each countries as c (c.country)}
					<div>
						<div class="mb-1 flex items-baseline justify-between text-sm">
							<span class="truncate">{c.country}</span>
							<span class="font-bold">{fmtK(c.count)}</span>
						</div>
						<div class="h-1.5 overflow-hidden rounded-full bg-muted">
							<div class="h-full rounded-full bg-primary" style="width: {Math.max(3, (c.count / countryMax) * 100)}%"></div>
						</div>
					</div>
				{:else}
					<p class="text-sm text-muted-foreground">Belum ada data geo serangan.</p>
				{/each}
			</CardContent>
		</Card>
	</div>

	<AttackMap />

	<!-- penalaran AI terakhir -->
	<Card>
		<CardHeader>
			<CardTitle>Penalaran AI terakhir</CardTitle>
			<CardDescription>Keputusan agent untuk trafik abu-abu</CardDescription>
		</CardHeader>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Waktu</TableHead>
						<TableHead>Backend</TableHead>
						<TableHead>Keputusan</TableHead>
						<TableHead>Conf</TableHead>
						<TableHead>Penalaran</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each agentRuns as r (r.ts + r.backend)}
						<TableRow>
							<TableCell class="text-muted-foreground">{fmtTime(r.ts)}</TableCell>
							<TableCell><Badge variant="secondary">{r.backend}</Badge></TableCell>
							<TableCell><Badge variant={decisionBadge(r.decision)}>{r.decision}</Badge></TableCell>
							<TableCell>{r.confidence}</TableCell>
							<TableCell>
								{#each r.reasoning ?? [] as line}
									<div class="text-xs text-muted-foreground">• {line}</div>
								{/each}
								{#if (r.indicators ?? []).length}
									<div class="text-xs text-muted-foreground">
										Indikator: <code class="rounded bg-input px-1">{r.indicators.join(", ")}</code>
									</div>
								{/if}
							</TableCell>
						</TableRow>
					{:else}
						<TableRow><TableCell colspan={5} class="text-center text-muted-foreground">Belum ada.</TableCell></TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>
