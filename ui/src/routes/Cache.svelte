<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtBytes } from "$lib/utils.js";
	import type { Site, CacheConfig, CacheStats } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import { Switch } from "$lib/components/ui/switch/index.js";
	import {
		Select,
		SelectTrigger,
		SelectContent,
		SelectItem,
	} from "$lib/components/ui/select/index.js";
	import { Trash2 } from "lucide-svelte";

	let sites = $state<Site[]>([]);
	let siteId = $state("");
	let cfg = $state<CacheConfig | null>(null);
	let stats = $state<CacheStats | null>(null);
	let saving = $state(false);
	let purging = $state(false);

	// form
	let enabled = $state(false);
	let ttl = $state("300");
	let maxEntries = $state("1000");
	let maxObjectKb = $state("512");
	let bypassCookies = $state("");

	async function loadSites() {
		try {
			sites = await apiGet<Site[]>("/api/sites");
			if (!siteId && sites.length) {
				siteId = sites[0].id;
				await loadSite();
			}
		} catch {
			toast("Gagal memuat website", { variant: "destructive" });
		}
	}

	async function loadSite() {
		cfg = null;
		stats = null;
		if (!siteId) return;
		try {
			const [c, s] = await Promise.all([
				apiGet<CacheConfig>(`/api/cache/config?site_id=${encodeURIComponent(siteId)}`),
				apiGet<CacheStats>(`/api/cache/stats?site_id=${encodeURIComponent(siteId)}`),
			]);
			cfg = c;
			stats = s;
			enabled = !!c.enabled;
			ttl = String(c.ttl ?? 300);
			maxEntries = String(c.max_entries ?? 1000);
			maxObjectKb = String(c.max_object_kb ?? 512);
			bypassCookies = (c.bypass_cookies ?? []).join(", ");
		} catch (e) {
			toast("Gagal memuat konfigurasi cache", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		}
	}

	async function save() {
		saving = true;
		try {
			await apiPost("/api/cache/config", {
				site_id: siteId,
				enabled,
				ttl: parseInt(ttl, 10) || 300,
				max_entries: parseInt(maxEntries, 10) || 1000,
				max_object_kb: parseInt(maxObjectKb, 10) || 512,
				bypass_cookies: bypassCookies
					.split(",")
					.map((x) => x.trim())
					.filter(Boolean),
			});
			toast("Konfigurasi cache tersimpan");
			await loadSite();
		} catch (e) {
			toast("Gagal menyimpan", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		} finally {
			saving = false;
		}
	}

	async function purge() {
		if (!confirm("Hapus seluruh cache untuk website ini?")) return;
		purging = true;
		try {
			const r = await apiPost<{ ok: boolean; purged: number }>("/api/cache/purge", { site_id: siteId });
			toast(`Cache dibersihkan (${r.purged} entri)`);
			await loadSite();
		} catch (e) {
			toast("Gagal purge", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		} finally {
			purging = false;
		}
	}

	let hitPct = $derived(
		stats ? (stats.hit_ratio * 100).toFixed(1) : null,
	);

	onMount(loadSites);
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Cache</h1>
		<p class="text-sm text-muted-foreground">
			Cache respons di sisi WAF — hanya GET, status 200/301/302, tanpa cookie sesi.
			Respons cache ditandai header <code class="rounded bg-input px-1">X-Perisai-Cache: HIT</code>.
		</p>
	</div>

	<Card>
		<CardContent class="flex flex-wrap items-end gap-4 pt-6">
			<div class="w-72 space-y-2">
				<Label>Website</Label>
				<Select type="single" bind:value={siteId} onValueChange={loadSite}>
					<SelectTrigger>{sites.find((s) => s.id === siteId)?.domain ?? "Pilih website…"}</SelectTrigger>
					<SelectContent>
						{#each sites as s (s.id)}
							<SelectItem value={s.id}>{s.domain}</SelectItem>
						{/each}
					</SelectContent>
				</Select>
			</div>
		</CardContent>
	</Card>

	{#if siteId}
		<div class="grid gap-6 md:grid-cols-2">
			<Card>
				<CardHeader>
					<CardTitle>Konfigurasi</CardTitle>
				</CardHeader>
				<CardContent class="space-y-4">
					<label class="flex items-center gap-3">
						<Switch bind:checked={enabled} />
						<span class="text-sm font-medium">Aktifkan cache</span>
					</label>
					<div class="grid grid-cols-2 gap-4">
						<div class="space-y-2">
							<Label for="c-ttl">TTL (detik)</Label>
							<Input id="c-ttl" bind:value={ttl} />
						</div>
						<div class="space-y-2">
							<Label for="c-max">Maks entri</Label>
							<Input id="c-max" bind:value={maxEntries} />
						</div>
					</div>
					<div class="space-y-2">
						<Label for="c-obj">Maks ukuran objek (KB)</Label>
						<Input id="c-obj" bind:value={maxObjectKb} />
					</div>
					<div class="space-y-2">
						<Label for="c-bypass">Bypass cookies (pisahkan koma)</Label>
						<Input id="c-bypass" bind:value={bypassCookies} placeholder="session_id, wordpress_logged_in" />
						<p class="text-xs text-muted-foreground">
							Request dengan cookie ini tidak di-cache (mis. user login).
						</p>
					</div>
					<Button onclick={save} disabled={saving}>{saving ? "Menyimpan…" : "💾 Simpan"}</Button>
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle>Statistik</CardTitle>
					<CardDescription>Hit ratio cache website ini</CardDescription>
				</CardHeader>
				<CardContent class="space-y-4">
					{#if stats}
						<div class="grid grid-cols-2 gap-4">
							<div><div class="text-3xl font-bold text-green-400">{hitPct}%</div><div class="text-xs text-muted-foreground">Hit ratio</div></div>
							<div><div class="text-3xl font-bold">{stats.entries}</div><div class="text-xs text-muted-foreground">Entri</div></div>
							<div><div class="text-2xl font-bold">{stats.hits.toLocaleString("id-ID")}</div><div class="text-xs text-muted-foreground">Hits</div></div>
							<div><div class="text-2xl font-bold">{stats.misses.toLocaleString("id-ID")}</div><div class="text-xs text-muted-foreground">Misses</div></div>
							<div><div class="text-2xl font-bold">{fmtBytes(stats.bytes)}</div><div class="text-xs text-muted-foreground">Ukuran</div></div>
						</div>
						<div class="h-2 overflow-hidden rounded-full bg-input">
							<div class="h-full rounded-full bg-green-500 transition-all" style="width: {hitPct}%"></div>
						</div>
					{:else}
						<p class="text-sm text-muted-foreground">Memuat…</p>
					{/if}
					<Button variant="destructive" onclick={purge} disabled={purging}>
						<Trash2 class="size-4" /> {purging ? "Membersihkan…" : "Purge seluruh cache"}
					</Button>
				</CardContent>
			</Card>
		</div>
	{/if}
</div>
