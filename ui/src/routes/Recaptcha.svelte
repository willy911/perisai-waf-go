<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import type { RecaptchaConfig, Site } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import { Switch } from "$lib/components/ui/switch/index.js";
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

	let cfg = $state<RecaptchaConfig | null>(null);
	let sites = $state<Site[]>([]);
	let enabled = $state(false);
	let siteKey = $state("");
	let secretKey = $state("");
	let mode = $state("v2");
	let saving = $state(false);

	async function load() {
		try {
			const [c, s] = await Promise.all([
				apiGet<RecaptchaConfig>("/api/recaptcha/config"),
				apiGet<Site[]>("/api/sites"),
			]);
			cfg = c;
			enabled = c.enabled;
			siteKey = c.site_key || "";
			mode = c.mode || "v2";
			sites = s;
		} catch {
			toast("Gagal memuat konfigurasi reCAPTCHA", { variant: "destructive" });
		}
	}

	async function save() {
		saving = true;
		try {
			const body: Record<string, unknown> = { enabled, mode };
			if (siteKey.trim()) body.site_key = siteKey.trim();
			if (secretKey.trim()) body.secret_key = secretKey.trim();
			await apiPost("/api/recaptcha/config", body);
			secretKey = "";
			toast("Konfigurasi reCAPTCHA tersimpan");
			await load();
		} catch (e) {
			toast("Gagal menyimpan", {
				description: e instanceof Error ? e.message : "",
				variant: "destructive",
			});
		} finally {
			saving = false;
		}
	}

	async function toggleSite(s: Site) {
		const cur = !!s.recaptcha_enabled;
		try {
			await apiPost(`/api/sites/${s.id}/recaptcha`, { enabled: !cur });
			toast(!cur ? `reCAPTCHA aktif untuk ${s.domain}` : `reCAPTCHA nonaktif untuk ${s.domain}`);
			await load();
		} catch (e) {
			toast("Gagal", { description: e instanceof Error ? e.message : "", variant: "destructive" });
		}
	}

	onMount(load);
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">ReCAPTCHA</h1>
		<p class="text-sm text-muted-foreground">
			Challenge Google reCAPTCHA sebagai alternatif JS challenge bawaan. Secret key tidak pernah ditampilkan kembali.
		</p>
	</div>

	<Card class="max-w-2xl">
		<CardHeader>
			<CardTitle>Konfigurasi global</CardTitle>
			<CardDescription>Dapatkan Site key & Secret key di google.com/recaptcha</CardDescription>
		</CardHeader>
		<CardContent class="space-y-4">
			<label class="flex items-center gap-3">
				<Switch bind:checked={enabled} />
				<span class="text-sm font-medium">Aktifkan reCAPTCHA</span>
			</label>
			<div class="space-y-2">
				<Label for="rc-sitekey">Site key</Label>
				<Input
					id="rc-sitekey"
					bind:value={siteKey}
					placeholder={cfg?.site_key_set ? "(sudah tersimpan — kosongkan bila tidak diubah)" : "site key dari Google"}
				/>
			</div>
			<div class="space-y-2">
				<Label for="rc-secret">Secret key</Label>
				<Input
					id="rc-secret"
					type="password"
					bind:value={secretKey}
					placeholder="kosongkan = tidak diubah"
					autocomplete="off"
				/>
			</div>
			<div class="w-64 space-y-2">
				<Label>Mode</Label>
				<Select type="single" bind:value={mode}>
					<SelectTrigger><SelectValue /></SelectTrigger>
					<SelectContent>
						<SelectItem value="v2">v2 — "Saya bukan robot" (checkbox)</SelectItem>
						<SelectItem value="v3">v3 — skor invisible</SelectItem>
					</SelectContent>
				</Select>
			</div>
			<Button onclick={save} disabled={saving}>{saving ? "Menyimpan…" : "💾 Simpan"}</Button>
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle>Aktif per website</CardTitle>
			<CardDescription>Bila site mengaktifkan reCAPTCHA, challenge menampilkan widget reCAPTCHA</CardDescription>
		</CardHeader>
		<CardContent class="p-0">
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>Domain</TableHead>
						<TableHead>Status</TableHead>
						<TableHead>Aksi</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{#each sites as s (s.id)}
						<TableRow>
							<TableCell class="font-semibold">{s.domain}</TableCell>
							<TableCell>
								<Switch checked={!!s.recaptcha_enabled} onCheckedChange={() => toggleSite(s)} disabled={!cfg?.enabled} />
							</TableCell>
							<TableCell class="text-sm text-muted-foreground">
								{s.recaptcha_enabled ? "aktif" : "nonaktif"}
							</TableCell>
						</TableRow>
					{:else}
						<TableRow><TableCell colspan={3} class="text-center text-muted-foreground">Belum ada website.</TableCell></TableRow>
					{/each}
				</TableBody>
			</Table>
		</CardContent>
	</Card>
</div>
