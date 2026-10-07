<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost, apiDel } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtDateTime } from "$lib/utils.js";
	import type { IpEntry } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
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
	import { Trash2 } from "lucide-svelte";

	let entries = $state<IpEntry[]>([]);
	let gIp = $state("");
	let gList = $state("black");
	let gHours = $state("");
	let gNote = $state("");
	let adding = $state(false);

	async function load() {
		try {
			entries = await apiGet<IpEntry[]>("/api/iplists");
		} catch {
			toast("Gagal memuat IP list", { variant: "destructive" });
		}
	}

	async function addIp() {
		if (!gIp.trim()) {
			toast("IP/CIDR wajib diisi", { variant: "destructive" });
			return;
		}
		adding = true;
		try {
			await apiPost("/api/iplists", {
				network: gIp.trim(),
				list: gList,
				expires_hours: parseFloat(gHours.trim() || "0") || 0,
				note: gNote.trim(),
			});
			gIp = "";
			gNote = "";
			gHours = "";
			toast("Entri ditambahkan");
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		} finally {
			adding = false;
		}
	}

	async function delIp(e: IpEntry) {
		if (!confirm(`Hapus ${e.network} dari ${e.list === "white" ? "whitelist" : "blacklist"}?`)) return;
		try {
			await apiDel(`/api/iplists/${e.id}`);
			toast("Entri dihapus");
			await load();
		} catch (err) {
			toast("Gagal", { description: err instanceof Error ? err.message : "", variant: "destructive" });
		}
	}

	onMount(load);
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Black/whitelist IP</h1>
		<p class="text-sm text-muted-foreground">Daftar IP/CIDR manual — whitelist menang atas blacklist & melewati semua pemeriksaan</p>
	</div>

	<Card>
		<CardHeader>
			<CardTitle>＋ Tambah IP / CIDR</CardTitle>
		</CardHeader>
		<CardContent>
			<div class="flex flex-wrap items-end gap-3">
				<div class="min-w-52 flex-1 space-y-2">
					<Label for="g-ip">IP / CIDR</Label>
					<Input id="g-ip" bind:value={gIp} placeholder="1.2.3.4 atau 1.2.3.0/24" class="font-mono" />
				</div>
				<div class="w-52 space-y-2">
					<Label>Daftar</Label>
					<Select type="single" bind:value={gList}>
						<SelectTrigger><SelectValue /></SelectTrigger>
						<SelectContent>
							<SelectItem value="black">⛔ Blacklist (blokir)</SelectItem>
							<SelectItem value="white">✅ Whitelist (lewati WAF)</SelectItem>
						</SelectContent>
					</Select>
				</div>
				<div class="w-44 space-y-2">
					<Label for="g-hours">Kedaluwarsa (jam)</Label>
					<Input id="g-hours" bind:value={gHours} placeholder="opsional" />
				</div>
				<div class="min-w-40 flex-1 space-y-2">
					<Label for="g-note">Catatan</Label>
					<Input id="g-note" bind:value={gNote} placeholder="catatan" />
				</div>
				<Button onclick={addIp} disabled={adding}>{adding ? "Menambah…" : "Tambah"}</Button>
			</div>
		</CardContent>
	</Card>

	<Card>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Network</TableHead>
						<TableHead>Daftar</TableHead>
						<TableHead>Scope</TableHead>
						<TableHead>Catatan</TableHead>
						<TableHead>Kedaluwarsa</TableHead>
						<TableHead>Aksi</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each entries as e (e.id)}
						{@const dead = e.expires_at && e.expires_at < Date.now() / 1000}
						<TableRow>
							<TableCell><code class="rounded bg-input px-1 text-xs">{e.network}</code></TableCell>
							<TableCell>
								<Badge variant={e.list === "white" ? "success" : "destructive"}>
									{e.list === "white" ? "whitelist" : "blacklist"}
								</Badge>
							</TableCell>
							<TableCell class="text-muted-foreground">{e.scope}</TableCell>
							<TableCell class="text-muted-foreground">{e.note || "-"}</TableCell>
							<TableCell class="text-muted-foreground">
								{#if dead}<span class="text-amber-400">⚠️ kedaluwarsa</span>
								{:else}{e.expires_at ? fmtDateTime(e.expires_at) : "permanen"}{/if}
							</TableCell>
							<TableCell>
								<Button size="sm" variant="destructive" onclick={() => delIp(e)}>
									<Trash2 class="size-3.5" />
								</Button>
							</TableCell>
						</TableRow>
					{:else}
						<TableRow><TableCell colspan={6} class="text-center text-muted-foreground">Belum ada entri.</TableCell></TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>
