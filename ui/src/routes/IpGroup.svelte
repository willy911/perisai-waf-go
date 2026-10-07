<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost, apiPut, apiDel } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtDateTime } from "$lib/utils.js";
	import type { IpGroup } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import { Textarea } from "$lib/components/ui/textarea/index.js";
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
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription,
		DialogFooter,
	} from "$lib/components/ui/dialog/index.js";
	import { Trash2, Plus, Pencil } from "lucide-svelte";

	let groups = $state<IpGroup[]>([]);

	// dialog grup (tambah/edit)
	let grpOpen = $state(false);
	let editing = $state<IpGroup | null>(null);
	let gName = $state("");
	let gKind = $state("black");
	let gDesc = $state("");
	let gSaving = $state(false);

	// dialog anggota
	let memOpen = $state(false);
	let memGroup = $state<IpGroup | null>(null);
	let mCidr = $state("");
	let mSaving = $state(false);

	async function load() {
		try {
			groups = await apiGet<IpGroup[]>("/api/ip-groups");
		} catch {
			toast("Gagal memuat IP group", { variant: "destructive" });
		}
	}

	function openNew() {
		editing = null;
		gName = "";
		gKind = "black";
		gDesc = "";
		grpOpen = true;
	}

	function openEdit(g: IpGroup) {
		editing = g;
		gName = g.name;
		gKind = g.kind;
		gDesc = g.description ?? "";
		grpOpen = true;
	}

	async function saveGroup() {
		if (!gName.trim()) {
			toast("Nama grup wajib diisi", { variant: "destructive" });
			return;
		}
		gSaving = true;
		try {
			if (editing) {
				await apiPut(`/api/ip-groups/${editing.id}`, {
					name: gName.trim(),
					description: gDesc.trim(),
				});
				toast("Grup diperbarui");
			} else {
				await apiPost("/api/ip-groups", {
					name: gName.trim(),
					kind: gKind,
					description: gDesc.trim(),
				});
				toast("Grup dibuat");
			}
			grpOpen = false;
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		} finally {
			gSaving = false;
		}
	}

	async function delGroup(g: IpGroup) {
		if (!confirm(`Hapus grup "${g.name}" beserta ${g.members.length} anggotanya?`)) return;
		try {
			await apiDel(`/api/ip-groups/${g.id}`);
			toast("Grup dihapus");
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	function openMembers(g: IpGroup) {
		memGroup = g;
		mCidr = "";
		memOpen = true;
	}

	async function addMember() {
		if (!memGroup || !mCidr.trim()) return;
		mSaving = true;
		try {
			await apiPost(`/api/ip-groups/${memGroup.id}/members`, { cidr: mCidr.trim() });
			mCidr = "";
			toast("Anggota ditambahkan");
			await load();
			memGroup = groups.find((x) => x.id === memGroup!.id) ?? null;
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		} finally {
			mSaving = false;
		}
	}

	async function delMember(g: IpGroup, cidr: string) {
		try {
			await apiDel(`/api/ip-groups/${g.id}/members`, { cidr });
			toast("Anggota dihapus");
			await load();
			memGroup = groups.find((x) => x.id === g.id) ?? null;
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	onMount(load);
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold">IP Group</h1>
			<p class="text-sm text-muted-foreground">
				Kelompok IP/CIDR bernama — anggota grup whitelist/blacklist diperlakukan sama seperti entri IP List
			</p>
		</div>
		<Button onclick={openNew}><Plus class="size-4" /> Grup baru</Button>
	</div>

	<Card>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Nama</TableHead>
						<TableHead>Tipe</TableHead>
						<TableHead>Deskripsi</TableHead>
						<TableHead>Anggota</TableHead>
						<TableHead>Dibuat</TableHead>
						<TableHead>Aksi</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each groups as g (g.id)}
						<TableRow>
							<TableCell class="font-semibold">{g.name}</TableCell>
							<TableCell>
								<Badge variant={g.kind === "white" ? "success" : "destructive"}>
									{g.kind === "white" ? "whitelist" : "blacklist"}
								</Badge>
							</TableCell>
							<TableCell class="text-muted-foreground">{g.description || "-"}</TableCell>
							<TableCell>
								<button class="text-sm text-primary hover:underline" onclick={() => openMembers(g)}>
									{g.members.length} IP/CIDR
								</button>
							</TableCell>
							<TableCell class="text-muted-foreground">{fmtDateTime(g.created_at)}</TableCell>
							<TableCell>
								<div class="flex gap-1">
									<Button size="sm" variant="outline" onclick={() => openEdit(g)}>
										<Pencil class="size-3.5" />
									</Button>
									<Button size="sm" variant="destructive" onclick={() => delGroup(g)}>
										<Trash2 class="size-3.5" />
									</Button>
								</div>
							</TableCell>
						</TableRow>
					{:else}
						<TableRow><TableCell colspan={6} class="text-center text-muted-foreground">Belum ada grup.</TableCell></TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>

<!-- dialog tambah/edit grup -->
<Dialog bind:open={grpOpen}>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>{editing ? "Ubah grup" : "Grup IP baru"}</DialogTitle>
			<DialogDescription>Tipe grup (whitelist/blacklist) tidak bisa diubah setelah dibuat.</DialogDescription>
		</DialogHeader>
		<div class="space-y-4">
			<div class="space-y-2">
				<Label for="gg-name">Nama</Label>
				<Input id="gg-name" bind:value={gName} placeholder="mis. kantor-pusat" />
			</div>
			{#if !editing}
				<div class="space-y-2">
					<Label>Tipe</Label>
					<Select type="single" bind:value={gKind}>
						<SelectTrigger><SelectValue /></SelectTrigger>
						<SelectContent>
							<SelectItem value="black">⛔ Blacklist (blokir)</SelectItem>
							<SelectItem value="white">✅ Whitelist (lewati WAF)</SelectItem>
						</SelectContent>
					</Select>
				</div>
			{/if}
			<div class="space-y-2">
				<Label for="gg-desc">Deskripsi</Label>
				<Textarea id="gg-desc" bind:value={gDesc} placeholder="opsional" rows={3} />
			</div>
		</div>
		<DialogFooter>
			<Button onclick={saveGroup} disabled={gSaving}>{gSaving ? "Menyimpan…" : "Simpan"}</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>

<!-- dialog anggota -->
<Dialog bind:open={memOpen}>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>Anggota — {memGroup?.name}</DialogTitle>
			<DialogDescription>Tambah/hapus IP atau CIDR dalam grup ini.</DialogDescription>
		</DialogHeader>
		<div class="flex gap-2">
			<Input bind:value={mCidr} placeholder="1.2.3.4 atau 1.2.3.0/24" class="font-mono"
				onkeydown={(e) => e.key === "Enter" && addMember()} />
			<Button onclick={addMember} disabled={mSaving}><Plus class="size-4" /> Tambah</Button>
		</div>
		<div class="max-h-64 space-y-1 overflow-auto">
			{#each memGroup?.members ?? [] as cidr (cidr)}
				<div class="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
					<code class="font-mono text-xs">{cidr}</code>
					<Button size="sm" variant="ghost" onclick={() => memGroup && delMember(memGroup, cidr)}>
						<Trash2 class="size-3.5 text-destructive" />
					</Button>
				</div>
			{:else}
				<p class="text-sm text-muted-foreground">Belum ada anggota.</p>
			{/each}
		</div>
	</DialogContent>
</Dialog>
