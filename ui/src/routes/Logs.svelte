<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet } from "$lib/api.js";
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

	let rows = $state<WafRequest[]>([]);
	let loading = $state(false);
	let filterDecision = $state("all");
	let search = $state("");

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
						<TableRow>
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
