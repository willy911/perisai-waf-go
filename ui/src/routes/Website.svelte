<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost, apiDel } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { fmtDate } from "$lib/utils.js";
	import type { Site, CfConfig } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import { Textarea } from "$lib/components/ui/textarea/index.js";
	import { Switch } from "$lib/components/ui/switch/index.js";
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
	import { Shield, Trash2, KeyRound, Cloud } from "lucide-svelte";

	let sites = $state<Site[]>([]);
	let cfConfig = $state<CfConfig | null>(null);

	// form tambah
	let fDomain = $state("");
	let fUpHost = $state("");
	let fUpPort = $state("");
	let fAgent = $state(true);
	let fTls = $state(false);
	let fPreserve = $state(true);
	let adding = $state(false);

	// dialog SSL
	let certOpen = $state(false);
	let certSite = $state<Site | null>(null);
	let certPem = $state("");
	let keyPem = $state("");
	let certMsg = $state("");
	let certSaving = $state(false);

	// dialog mapping zone CF
	let zoneOpen = $state(false);
	let zoneSite = $state<Site | null>(null);
	let zoneId = $state("");
	let zoneName = $state("");
	let zoneSaving = $state(false);

	async function load() {
		try {
			sites = await apiGet<Site[]>("/api/sites");
		} catch (e) {
			toast("Gagal memuat daftar website", { variant: "destructive" });
		}
		try {
			cfConfig = await apiGet<CfConfig>("/api/cf/config");
		} catch {
			cfConfig = null;
		}
	}

	async function addSite() {
		if (!fDomain.trim()) {
			toast("Domain wajib diisi", { variant: "destructive" });
			return;
		}
		adding = true;
		try {
			await apiPost("/api/sites", {
				domain: fDomain.trim(),
				upstream_host: fUpHost.trim() || "127.0.0.1",
				upstream_port: parseInt(fUpPort.trim() || "8000", 10),
				agent_enabled: fAgent,
				upstream_tls: fTls,
				preserve_host: fPreserve,
			});
			fDomain = "";
			fUpHost = "";
			fUpPort = "";
			toast("Website ditambahkan");
			await load();
		} catch (e) {
			toast("Gagal menambah website", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		} finally {
			adding = false;
		}
	}

	async function toggleSite(s: Site) {
		try {
			await apiPost(`/api/sites/${s.id}/toggle`);
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	async function toggleDdos(s: Site) {
		try {
			const r = await apiPost<{ ok: boolean; ddos_mode: boolean }>(`/api/sites/${s.id}/ddos`);
			toast(r.ddos_mode ? `🛡️ Mode Serangan AKTIF untuk ${s.domain}` : `Mode Serangan nonaktif untuk ${s.domain}`);
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	async function toggleRecaptcha(s: Site) {
		const cur = !!s.recaptcha_enabled;
		try {
			await apiPost(`/api/sites/${s.id}/recaptcha`, { enabled: !cur });
			toast(!cur ? "reCAPTCHA diaktifkan" : "reCAPTCHA dinonaktifkan");
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	async function delSite(s: Site) {
		if (!confirm(`Hapus ${s.domain} dari proteksi?`)) return;
		try {
			await apiDel(`/api/sites/${s.id}`);
			toast("Website dihapus");
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	function openCert(s: Site) {
		certSite = s;
		certPem = "";
		keyPem = "";
		certMsg = "";
		certOpen = true;
	}

	async function saveCert() {
		if (!certSite) return;
		certSaving = true;
		certMsg = "Menyimpan…";
		try {
			const r = await apiPost<{
				ok: boolean;
				need_restart?: boolean;
				domain_match?: boolean;
			}>(`/api/sites/${certSite.id}/cert`, { cert_pem: certPem, key_pem: keyPem });
			certMsg =
				"✅ Tersimpan" +
				(r.need_restart ? " — restart WAF agar TLS aktif." : " — langsung aktif tanpa restart.") +
				(r.domain_match === false ? " ⚠️ Nama domain tidak cocok dengan isi sertifikat." : "");
			toast("Sertifikat tersimpan");
			await load();
		} catch (e) {
			certMsg = "❌ " + (e instanceof Error ? e.message : "gagal");
		} finally {
			certSaving = false;
		}
	}

	async function delCert() {
		if (!certSite || !confirm("Hapus sertifikat situs ini?")) return;
		try {
			await apiDel(`/api/sites/${certSite.id}/cert`);
			certMsg = "✅ Sertifikat dihapus.";
			toast("Sertifikat dihapus");
			await load();
		} catch (e) {
			certMsg = "❌ " + (e instanceof Error ? e.message : "gagal");
		}
	}

	function zoneFor(siteId: string): string {
		return cfConfig?.zones.find((z) => z.site_id === siteId)?.zone_name ?? "—";
	}

	function openZone(s: Site) {
		zoneSite = s;
		const z = cfConfig?.zones.find((x) => x.site_id === s.id);
		zoneId = z?.zone_id ?? "";
		zoneName = z?.zone_name ?? s.domain;
		zoneOpen = true;
	}

	async function saveZone() {
		if (!zoneSite) return;
		zoneSaving = true;
		try {
			const zones = (cfConfig?.zones ?? []).filter((z) => z.site_id !== zoneSite!.id);
			if (zoneId.trim()) {
				zones.push({ site_id: zoneSite.id, zone_id: zoneId.trim(), zone_name: zoneName.trim() || zoneSite.domain });
			}
			await apiPost("/api/cf/config", { zones });
			toast("Mapping zone tersimpan");
			zoneOpen = false;
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		} finally {
			zoneSaving = false;
		}
	}

	onMount(load);
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Website</h1>
		<p class="text-sm text-muted-foreground">Domain yang dilindungi WAF</p>
	</div>

	<Card>
		<CardHeader>
			<CardTitle>＋ Tambah website dilindungi</CardTitle>
			<CardDescription>
				Arahkan DNS domain ke IP server WAF ini. Isi IP website tujuan + port aplikasinya
				(mis. 80, 443 bila HTTPS, 8000). Untuk HTTPS: setelah tambah, klik 🔒 SSL di tabel lalu paste sertifikat.
			</CardDescription>
		</CardHeader>
		<CardContent>
			<div class="flex flex-wrap items-end gap-3">
				<div class="min-w-40 flex-1 space-y-2">
					<Label for="f-domain">Domain</Label>
					<Input id="f-domain" bind:value={fDomain} placeholder="domain.com" />
				</div>
				<div class="min-w-40 flex-1 space-y-2">
					<Label for="f-uphost">IP website tujuan</Label>
					<Input id="f-uphost" bind:value={fUpHost} placeholder="103.147.9.20" />
				</div>
				<div class="w-32 space-y-2">
					<Label for="f-upport">Port</Label>
					<Input id="f-upport" bind:value={fUpPort} placeholder="80/443/8000" />
				</div>
				<label class="flex items-center gap-2 text-sm">
					<Switch bind:checked={fAgent} /> AI agent
				</label>
				<label class="flex items-center gap-2 text-sm" title="Upstream diakses via HTTPS">
					<Switch bind:checked={fTls} /> Upstream HTTPS
				</label>
				<label class="flex items-center gap-2 text-sm" title="Teruskan Host header asli domain ke upstream">
					<Switch bind:checked={fPreserve} /> Host asli
				</label>
				<Button onclick={addSite} disabled={adding}>{adding ? "Menambah…" : "Tambah"}</Button>
			</div>
		</CardContent>
	</Card>

	<Card>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Domain</TableHead>
						<TableHead>Upstream</TableHead>
						<TableHead>SSL</TableHead>
						<TableHead>Status</TableHead>
						<TableHead>AI Agent</TableHead>
						<TableHead>DDoS</TableHead>
						<TableHead>reCAPTCHA</TableHead>
						<TableHead>CF Zone</TableHead>
						<TableHead>Req/24j</TableHead>
						<TableHead>Aksi</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each sites as s (s.id)}
						<TableRow>
							<TableCell class="font-semibold">{s.domain}</TableCell>
							<TableCell>
								<code class="rounded bg-input px-1 text-xs">{s.upstream_tls ? "https" : "http"}://{s.upstream_host}:{s.upstream_port}</code>
							</TableCell>
							<TableCell>
								{#if s.tls_cert}
									<Badge variant="success" title={s.tls_cert}>🔒 {s.tls_expires_at ? "s/d " + fmtDate(s.tls_expires_at) : "aktif"}</Badge>
								{:else}
									<span class="text-muted-foreground">—</span>
								{/if}
							</TableCell>
							<TableCell>
								<Badge variant={s.enabled ? "success" : "destructive"}>{s.enabled ? "aktif" : "nonaktif"}</Badge>
							</TableCell>
							<TableCell>
								<Badge variant={s.agent_enabled ? "default" : "destructive"}>{s.agent_enabled ? "on" : "off"}</Badge>
							</TableCell>
							<TableCell>
								<Button
									size="sm"
									variant={s.ddos_mode ? "destructive" : "outline"}
									onclick={() => toggleDdos(s)}
									title="Mode Serangan: challenge-first + rate limit ketat"
								>
									<Shield class="size-4" /> {s.ddos_mode ? "ON" : "OFF"}
								</Button>
							</TableCell>
							<TableCell>
								<Switch checked={!!s.recaptcha_enabled} onCheckedChange={() => toggleRecaptcha(s)} />
							</TableCell>
							<TableCell>
								{#if cfConfig}
									<button class="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground" onclick={() => openZone(s)} title="Atur mapping zone">
										<Cloud class="size-3.5" /> {zoneFor(s.id)}
									</button>
								{:else}
									<span class="text-xs text-muted-foreground">—</span>
								{/if}
							</TableCell>
							<TableCell>{s.requests_24h ?? 0}</TableCell>
							<TableCell>
								<div class="flex flex-wrap gap-1">
									<Button size="sm" variant="outline" onclick={() => toggleSite(s)}>
										{s.enabled ? "Nonaktifkan" : "Aktifkan"}
									</Button>
									<Button size="sm" variant="outline" onclick={() => openCert(s)}>
										<KeyRound class="size-3.5" /> SSL
									</Button>
									<Button size="sm" variant="destructive" onclick={() => delSite(s)}>
										<Trash2 class="size-3.5" />
									</Button>
								</div>
							</TableCell>
						</TableRow>
					{:else}
						<TableRow>
							<TableCell colspan={10} class="text-center text-muted-foreground">
								Belum ada website. Tambahkan domain pertama di atas.
							</TableCell>
						</TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>

<!-- dialog SSL -->
<Dialog bind:open={certOpen}>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>🔒 Sertifikat SSL — {certSite?.domain}</DialogTitle>
			<DialogDescription>
				Paste isi file sertifikat (fullchain.pem) dan private key. WAF menyajikannya via SNI untuk domain ini.
			</DialogDescription>
		</DialogHeader>
		<div class="space-y-3">
			<div class="space-y-2">
				<Label for="cert-pem">Sertifikat (PEM)</Label>
				<Textarea id="cert-pem" rows={7} bind:value={certPem} placeholder="-----BEGIN CERTIFICATE-----" class="font-mono text-xs" />
			</div>
			<div class="space-y-2">
				<Label for="key-pem">Private key (PEM)</Label>
				<Textarea id="key-pem" rows={7} bind:value={keyPem} placeholder="-----BEGIN PRIVATE KEY-----" class="font-mono text-xs" />
			</div>
			{#if certMsg}
				<p class="text-sm text-muted-foreground">{certMsg}</p>
			{/if}
		</div>
		<DialogFooter>
			<Button variant="destructive" onclick={delCert}>Hapus</Button>
			<Button onclick={saveCert} disabled={certSaving}>{certSaving ? "Menyimpan…" : "Simpan"}</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>

<!-- dialog mapping zone CF -->
<Dialog bind:open={zoneOpen}>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>☁️ Mapping Zone Cloudflare — {zoneSite?.domain}</DialogTitle>
			<DialogDescription>
				Hubungkan website ini ke zone Cloudflare agar statistik & purge cache bisa dipakai dari dashboard.
				Kosongkan Zone ID untuk melepas mapping.
			</DialogDescription>
		</DialogHeader>
		<div class="space-y-3">
			<div class="space-y-2">
				<Label for="zone-id">Zone ID</Label>
				<Input id="zone-id" bind:value={zoneId} placeholder="0123456789abcdef…" class="font-mono" />
			</div>
			<div class="space-y-2">
				<Label for="zone-name">Nama zone</Label>
				<Input id="zone-name" bind:value={zoneName} placeholder="domain.com" />
			</div>
		</div>
		<DialogFooter>
			<Button onclick={saveZone} disabled={zoneSaving}>{zoneSaving ? "Menyimpan…" : "Simpan"}</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
