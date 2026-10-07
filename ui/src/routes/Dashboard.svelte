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
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Dashboard</h1>
		<p class="text-sm text-muted-foreground">Ringkasan proteksi 24 jam terakhir</p>
	</div>

	<!-- kartu statistik -->
	<div class="grid grid-cols-2 gap-4 md:grid-cols-5">
		<Card><CardContent class="pt-6"><div class="text-3xl font-bold">{stats?.total ?? "…"}</div><div class="mt-1 text-xs text-muted-foreground">Request (24 jam)</div></CardContent></Card>
		<Card><CardContent class="pt-6"><div class="text-3xl font-bold text-green-400">{stats ? (d.allow ?? 0) : "…"}</div><div class="mt-1 text-xs text-muted-foreground">Allow</div></CardContent></Card>
		<Card><CardContent class="pt-6"><div class="text-3xl font-bold text-amber-400">{(d.challenge ?? 0) + (d.cache_hit ?? 0) > 0 ? (d.challenge ?? 0) + (d.cache_hit ?? 0) : (stats ? 0 : "…")}</div><div class="mt-1 text-xs text-muted-foreground">Challenge</div></CardContent></Card>
		<Card><CardContent class="pt-6"><div class="text-3xl font-bold text-red-400">{(d.block ?? 0) + (d.rate_limited ?? 0) > 0 ? (d.block ?? 0) + (d.rate_limited ?? 0) : (stats ? 0 : "…")}</div><div class="mt-1 text-xs text-muted-foreground">Block</div></CardContent></Card>
		<Card><CardContent class="pt-6"><div class="text-3xl font-bold">{stats?.rules_loaded ?? "…"}</div><div class="mt-1 text-xs text-muted-foreground">Signature aktif</div></CardContent></Card>
	</div>

	{#if stats?.top_offenders?.length}
		<p class="text-sm text-muted-foreground">
			Top offender: <code class="rounded bg-input px-1">{stats.top_offenders[0].ip}</code>
			({stats.top_offenders[0].count}x)
		</p>
	{/if}

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
							<div><div class="text-2xl font-bold text-red-400">{cfStats.threats.toLocaleString("id-ID")}</div><div class="text-xs text-muted-foreground">Threats</div></div>
							<div><div class="text-2xl font-bold text-green-400">{cfStats.cached_pct}%</div><div class="text-xs text-muted-foreground">Cached</div></div>
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

	<TrendChart {requests} />

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
