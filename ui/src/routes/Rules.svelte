<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtTime } from "$lib/utils.js";
	import type { ProposedRule, BuiltinRule } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import {
		Table,
		TableHeader,
		TableBody,
		TableRow,
		TableHead,
		TableCell,
	} from "$lib/components/ui/table/index.js";
	import { Check, X } from "lucide-svelte";

	let proposed = $state<ProposedRule[]>([]);
	let rules = $state<BuiltinRule[]>([]);
	let disabledIds = $state<Set<string>>(new Set());

	async function load() {
		try {
			const [p, r] = await Promise.all([
				apiGet<ProposedRule[]>("/api/proposed"),
				apiGet<BuiltinRule[]>("/api/rules"),
			]);
			proposed = p;
			rules = r;
		} catch {
			toast("Gagal memuat aturan", { variant: "destructive" });
		}
	}

	async function moderate(id: number, act: "approve" | "reject") {
		try {
			await apiPost(`/api/proposed/${id}/${act}`);
			toast(act === "approve" ? "Usulan disetujui → jadi custom rule" : "Usulan ditolak");
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	async function toggleRule(r: BuiltinRule) {
		try {
			await apiPost(`/api/rules/${r.id}/toggle`);
			if (disabledIds.has(r.id)) {
				disabledIds.delete(r.id);
			} else {
				disabledIds.add(r.id);
			}
			disabledIds = new Set(disabledIds);
			await load();
		} catch (e) {
			toast("Gagal toggle rule", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		}
	}

	function sevVariant(s: string): "destructive" | "warning" | "secondary" {
		const v = s.toLowerCase();
		if (v.includes("critical") || v.includes("high")) return "destructive";
		if (v.includes("medium")) return "warning";
		return "secondary";
	}

	onMount(load);
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Custom rule</h1>
		<p class="text-sm text-muted-foreground">Usulan aturan dari auto-learning & daftar signature</p>
	</div>

	<Card>
		<CardHeader>
			<CardTitle>Usulan aturan {proposed.length ? `(${proposed.length})` : ""}</CardTitle>
			<CardDescription>
				Aturan yang dipelajari otomatis dari penalaran AI. Setujui untuk mengaktifkannya langsung.
			</CardDescription>
		</CardHeader>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Waktu</TableHead>
						<TableHead>Aturan</TableHead>
						<TableHead>Pattern</TableHead>
						<TableHead>Catatan</TableHead>
						<TableHead>Aksi</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each proposed as p (p.id)}
						<TableRow>
							<TableCell class="whitespace-nowrap text-muted-foreground">{fmtTime(p.ts)}</TableCell>
							<TableCell>
								<div class="font-semibold">{p.rule.name}</div>
								<div class="text-xs text-muted-foreground">{p.rule.id} · {p.rule.category} · {p.rule.severity}</div>
							</TableCell>
							<TableCell><code class="rounded bg-input px-1 text-xs">{p.rule.pattern}</code></TableCell>
							<TableCell class="text-muted-foreground">
								{p.note || ""}
								<div class="text-xs">sumber: {p.source}</div>
							</TableCell>
							<TableCell>
								<div class="flex gap-1">
									<Button size="sm" onclick={() => moderate(p.id, "approve")}>
										<Check class="size-3.5" /> Setujui
									</Button>
									<Button size="sm" variant="destructive" onclick={() => moderate(p.id, "reject")}>
										<X class="size-3.5" /> Tolak
									</Button>
								</div>
							</TableCell>
						</TableRow>
					{:else}
						<TableRow><TableCell colspan={5} class="text-center text-muted-foreground">Belum ada usulan aturan.</TableCell></TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle>Signature & custom rules ({rules.length})</CardTitle>
			<CardDescription>Klik toggle untuk mengaktifkan/menonaktifkan signature</CardDescription>
		</CardHeader>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>ID</TableHead>
						<TableHead>Nama</TableHead>
						<TableHead>Kategori</TableHead>
						<TableHead>Severity</TableHead>
						<TableHead>Bobot</TableHead>
						<TableHead>Status</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each rules as r (r.id)}
						<TableRow>
							<TableCell><code class="rounded bg-input px-1 text-xs">{r.id}</code></TableCell>
							<TableCell>{r.name}</TableCell>
							<TableCell class="text-muted-foreground">{r.category}</TableCell>
							<TableCell><Badge variant={sevVariant(r.severity)}>{r.severity}</Badge></TableCell>
							<TableCell>{r.weight}</TableCell>
							<TableCell>
								<Button size="sm" variant={disabledIds.has(r.id) ? "outline" : "secondary"} onclick={() => toggleRule(r)}>
									{disabledIds.has(r.id) ? "Aktifkan" : "Nonaktifkan"}
								</Button>
							</TableCell>
						</TableRow>
					{:else}
						<TableRow><TableCell colspan={6} class="text-center text-muted-foreground">Memuat…</TableCell></TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>
