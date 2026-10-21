<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtTime } from "$lib/utils.js";
	import type { WafRequest } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import {
		Select,
		SelectTrigger,
		SelectValue,
		SelectContent,
		SelectItem,
	} from "$lib/components/ui/select/index.js";
	import {
		Table,
		TableHeader,
		TableBody,
		TableRow,
		TableHead,
		TableCell,
	} from "$lib/components/ui/table/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { RefreshCw } from "lucide-svelte";
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription,
	} from "$lib/components/ui/dialog/index.js";

	let rows = $state<WafRequest[]>([]);
	let loading = $state(false);
	let filterDecision = $state("all");
	let search = $state("");

	// dialog detail + AI analysis
	let detailOpen = $state(false);
	let detail = $state<WafRequest | null>(null);
	let detailLoading = $state(false);
	let analysis = $state("");
	let analyzing = $state(false);
	let analysisErr = $state("");
	let ruleStatus = $state<{ status: string; by?: string; id?: string; name?: string; auto_approved?: boolean; duplicate?: boolean } | null>(null);

	async function openDetail(r: WafRequest) {
		detail = null;
		analysis = "";
		analysisErr = "";
		ruleStatus = null;
		detailLoading = true;
		detailOpen = true;
		try {
			detail = await apiGet<WafRequest>(`/api/requests/${r.id}`);
		} catch {
			toast("Gagal memuat detail log", { variant: "destructive" });
			detailOpen = false;
		} finally {
			detailLoading = false;
		}
	}

	async function runAnalysis() {
		if (!detail || analyzing) return;
		analyzing = true;
		analysisErr = "";
		try {
			const res = await apiPost<{ analysis: string; rule?: typeof ruleStatus }>(
				`/api/requests/${detail.id}/analyze`, {});
			analysis = res.analysis;
			ruleStatus = res.rule ?? null;
		} catch (e) {
			analysisErr = e instanceof Error ? e.message : "gagal";
		} finally {
			analyzing = false;
		}
	}

	function rawRequest(d: WafRequest): string {
		const lines = [`${d.method} ${d.path}${d.query ? "?" + d.query : ""} HTTP/1.1`];
		try {
			const h = JSON.parse(d.headers || "{}");
			for (const [k, v] of Object.entries(h)) lines.push(`${k}: ${v}`);
		} catch { /* abaikan */ }
		if (d.body) lines.push("", d.body);
		return lines.join("\n");
	}

	async function load() {
		loading = true;
		try {
			rows = await apiGet<WafRequest[]>("/api/requests?limit=200");
		} catch {
			toast("Gagal memuat log", { variant: "destructive" });
		} finally {
			loading = false;
		}
	}

	function badgeVariant(d: string): "success" | "warning" | "destructive" | "secondary" {
		if (d === "allow") return "success";
		if (d === "challenge" || d === "cache_hit") return "warning";
		if (d === "block" || d === "rate_limited") return "destructive";
		return "secondary";
	}

	let filtered = $derived(
		rows.filter((r) => {
			if (filterDecision !== "all" && r.decision !== filterDecision) return false;
			const q = search.trim().toLowerCase();
			if (q && !(r.ip.toLowerCase().includes(q) || r.path.toLowerCase().includes(q))) return false;
			return true;
		}),
	);

	onMount(() => {
		load();
		const t = setInterval(load, 10000);
		return () => clearInterval(t);
	});
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold">Interceptions logs</h1>
			<p class="text-sm text-muted-foreground">200 permintaan terakhir yang diproses WAF</p>
		</div>
		<Button variant="outline" size="sm" onclick={load} disabled={loading}>
			<RefreshCw class="size-4 {loading ? 'animate-spin' : ''}" /> Muat ulang
		</Button>
	</div>

	<Card>
		<CardContent class="flex flex-wrap items-end gap-4 pt-6">
			<div class="w-52 space-y-2">
				<Label>Keputusan</Label>
				<Select type="single" bind:value={filterDecision}>
					<SelectTrigger><SelectValue /></SelectTrigger>
					<SelectContent>
						<SelectItem value="all">Semua</SelectItem>
						<SelectItem value="allow">allow</SelectItem>
						<SelectItem value="challenge">challenge</SelectItem>
						<SelectItem value="block">block</SelectItem>
						<SelectItem value="rate_limited">rate_limited</SelectItem>
						<SelectItem value="cache_hit">cache_hit</SelectItem>
					</SelectContent>
				</Select>
			</div>
			<div class="min-w-52 flex-1 space-y-2">
				<Label for="log-search">Cari IP / path</Label>
				<Input id="log-search" bind:value={search} placeholder="1.2.3.4 atau /wp-login.php" />
			</div>
		</CardContent>
	</Card>

	<Card>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Waktu</TableHead>
						<TableHead>IP</TableHead>
						<TableHead>Request</TableHead>
						<TableHead>Skor</TableHead>
						<TableHead>Keputusan</TableHead>
						<TableHead>Aturan</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each filtered as r (r.id)}
						<TableRow class="cursor-pointer hover:bg-muted/50" onclick={() => openDetail(r)}>
							<TableCell class="whitespace-nowrap text-muted-foreground">{fmtTime(r.ts)}</TableCell>
							<TableCell><code class="rounded bg-input px-1 text-xs">{r.ip}</code></TableCell>
							<TableCell class="max-w-md">
								<code class="block truncate text-xs">{r.method} {r.path}{r.query ? "?" + r.query.slice(0, 60) : ""}</code>
								{#if r.agent_conf}
									<div class="text-xs text-muted-foreground">AI conf: {r.agent_conf}</div>
								{/if}
							</TableCell>
							<TableCell>{r.score}</TableCell>
							<TableCell><Badge variant={badgeVariant(r.decision)}>{r.decision}</Badge></TableCell>
							<TableCell class="text-muted-foreground">{r.top_rule || "-"}</TableCell>
						</TableRow>
					{:else}
						<TableRow>
							<TableCell colspan={6} class="text-center text-muted-foreground">
								{loading ? "Memuat…" : "Tidak ada log yang cocok."}
							</TableCell>
						</TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>

<!-- dialog detail log + AI analysis -->
<Dialog bind:open={detailOpen}>
	<DialogContent class="max-h-[90vh] max-w-3xl overflow-y-auto">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				{#if detail}
					<Badge variant={badgeVariant(detail.decision)}>{detail.decision}</Badge>
					<span class="font-mono text-sm font-normal">{detail.method} {detail.path}</span>
				{:else}
					Detail log
				{/if}
			</DialogTitle>
			<DialogDescription>Klik baris log untuk melihat detail forensik request.</DialogDescription>
		</DialogHeader>
		{#if detailLoading}
			<p class="py-8 text-center text-sm text-muted-foreground">Memuat…</p>
		{:else if detail}
			<div class="space-y-4">
				<dl class="grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 text-sm">
					<dt class="text-muted-foreground">Attack IP</dt>
					<dd><code class="rounded bg-input px-1 font-mono text-xs">{detail.ip}</code></dd>
					<dt class="text-muted-foreground">Payload</dt>
					<dd><code class="break-all rounded bg-input px-1 font-mono text-xs">{detail.query || detail.path || "-"}</code></dd>
					<dt class="text-muted-foreground">Module</dt>
					<dd class="font-semibold">{detail.top_rule || "-"}</dd>
					<dt class="text-muted-foreground">Skor</dt>
					<dd>{detail.score}</dd>
					<dt class="text-muted-foreground">Time</dt>
					<dd class="font-mono text-xs">{fmtTime(detail.ts)}</dd>
					<dt class="text-muted-foreground">ID</dt>
					<dd class="font-mono text-xs">{detail.id}</dd>
				</dl>
				<div>
					<div class="mb-1 text-xs font-semibold uppercase text-muted-foreground">Raw request</div>
					<pre class="max-h-56 overflow-auto rounded bg-muted p-3 font-mono text-xs whitespace-pre-wrap">{rawRequest(detail)}</pre>
				</div>
				<div>
					{#if analysis}
						<div class="mb-1 text-xs font-semibold uppercase text-muted-foreground">Hasil AI Analysis</div>
						<div class="rounded border border-indigo-200 bg-indigo-50 p-3 text-sm whitespace-pre-wrap dark:border-indigo-900 dark:bg-indigo-950">{analysis}</div>
					{:else if analysisErr}
						<p class="text-sm text-destructive">❌ {analysisErr}</p>
					{/if}
					{#if ruleStatus && ruleStatus.status === "covered"}
						<p class="text-sm text-green-700 dark:text-green-400">✓ Sudah tercakup aturan <code class="font-mono">{ruleStatus.by}</code> — tidak perlu rule baru.</p>
					{:else if ruleStatus && ruleStatus.status === "proposed"}
						<p class="text-sm text-amber-700 dark:text-amber-400">
							＋ Aturan baru diusulkan: <code class="font-mono">{ruleStatus.id}</code>{ruleStatus.name ? ` (${ruleStatus.name})` : ""}
							{#if ruleStatus.duplicate}
								(sudah ada di antrean usulan)
							{:else if ruleStatus.auto_approved}
								(sudah otomatis disetujui)
							{:else}
								— cek halaman Rules → Usulan aturan untuk menyetujui
							{/if}
						</p>
					{/if}
					<div class="mt-2 flex items-center gap-2">
						<Button
							onclick={runAnalysis}
							disabled={analyzing || !detail.ai_ready}
							class="bg-gradient-to-r from-indigo-400 to-indigo-600 text-white"
							title={detail.ai_ready ? "Analisis serangan dengan AI" : "Isi base_url AI general di Pengaturan → AI dulu"}
						>
							{analyzing ? "Menganalisis…" : "✨ AI Analysis"}
						</Button>
						{#if !detail.ai_ready}
							<span class="text-xs text-muted-foreground">AI general belum dikonfigurasi (Pengaturan → AI).</span>
						{/if}
					</div>
				</div>
			</div>
		{/if}
	</DialogContent>
</Dialog>
