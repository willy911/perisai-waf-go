<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet, apiPost, getToken, clearToken } from "$lib/api.js";
	import { toast, markAuthed } from "$lib/stores.js";
	import type { AiConfig, ModelInfo, SystemOneConfig } from "$lib/types.js";
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

	let backend = $state("auto");
	let baseUrl = $state("");
	let apiKey = $state("");
	let clearKey = $state(false);
	let model = $state("");
	let minConf = $state("0.55");
	let timeout = $state("20");
	let keySetHint = $state("");
	let status = $state("");

	let models = $state<ModelInfo[]>([]);
	let modelSearch = $state("");
	let showModelList = $state(false);
	let fetchingModels = $state(false);
	let saving = $state(false);
	let testing = $state(false);

	// ---- System One ----
	let s1Enabled = $state(true);
	let s1Endpoint = $state("");
	let s1ApiKey = $state("");
	let s1ClearKey = $state(false);
	let s1Model = $state("");
	let s1Timeout = $state("10");
	let s1KeySetHint = $state("");
	let s1Status = $state("");
	let s1Saving = $state(false);
	let s1Testing = $state(false);

	async function loadSystemOne() {
		try {
			const c = await apiGet<SystemOneConfig>("/api/systemone-config");
			s1Enabled = c.enabled;
			s1Endpoint = c.endpoint || "";
			s1Model = c.model || "";
			s1Timeout = String(c.timeout);
			s1ApiKey = "";
			s1ClearKey = false;
			s1KeySetHint = c.api_key_set ? "🔑 API key sudah tersimpan." : "⚠️ API key belum diisi.";
		} catch {
			toast("Gagal memuat konfigurasi System One", { variant: "destructive" });
		}
	}

	async function saveSystemOne() {
		s1Saving = true;
		s1Status = "menyimpan…";
		try {
			const body: Record<string, unknown> = {
				enabled: s1Enabled,
				endpoint: s1Endpoint.trim(),
				model: s1Model.trim(),
				timeout: parseInt(s1Timeout, 10),
			};
			if (s1ApiKey) body.api_key = s1ApiKey;
			if (s1ClearKey) body.clear_api_key = true;
			const r = await apiPost<{ ok: boolean; persisted: boolean; error?: string }>("/api/systemone-config", body);
			s1Status = r.persisted ? "✅ Tersimpan & berlaku langsung." : "✅ Diterapkan (file config tak ditulis).";
			toast("Pengaturan System One tersimpan");
			await loadSystemOne();
		} catch (e) {
			s1Status = "❌ " + (e instanceof Error ? e.message : "gagal");
		} finally {
			s1Saving = false;
		}
	}

	async function testSystemOne() {
		s1Testing = true;
		s1Status = "menghubungi…";
		try {
			const r = await apiGet<{ ok: boolean; model?: string; latency_ms?: number; p_test?: number; error?: string }>("/api/systemone/test");
			s1Status = r.ok ? `✅ OK — ${r.model} (${r.latency_ms} ms)` : `❌ Gagal: ${r.error}`;
		} catch (e) {
			s1Status = "❌ " + (e instanceof Error ? e.message : "gagal");
		} finally {
			s1Testing = false;
		}
	}

	async function load() {
		try {
			const c = await apiGet<AiConfig>("/api/ai-config");
			backend = c.backend;
			baseUrl = c.llm.base_url || "";
			model = c.llm.model || "";
			minConf = String(c.min_confidence);
			timeout = String(c.llm.timeout);
			apiKey = "";
			clearKey = false;
			keySetHint = c.llm.api_key_set ? "🔑 API key sudah tersimpan." : "⚠️ API key belum diisi.";
		} catch {
			toast("Gagal memuat konfigurasi AI", { variant: "destructive" });
		}
	}

	let filteredModels = $derived(
		models
			.filter((m) => m.id.toLowerCase().includes(modelSearch.trim().toLowerCase()))
			.slice(0, 60),
	);

	async function fetchModels() {
		fetchingModels = true;
		status = "mengambil daftar model…";
		try {
			const r = await apiPost<{ ok: boolean; models: ModelInfo[]; count: number; error?: string }>(
				"/api/ai-models",
				{ base_url: baseUrl.trim(), api_key: apiKey },
			);
			if (r.ok) {
				models = r.models || [];
				status = `✅ ${r.count} model ditemukan — ketik untuk mencari.`;
				showModelList = true;
			} else {
				status = "❌ " + (r.error || "gagal");
			}
		} catch (e) {
			status = "❌ " + (e instanceof Error ? e.message : "gagal");
		} finally {
			fetchingModels = false;
		}
	}

	function pickModel(id: string) {
		model = id;
		modelSearch = "";
		showModelList = false;
	}

	async function save() {
		saving = true;
		status = "menyimpan…";
		try {
			const body: Record<string, unknown> = {
				backend,
				base_url: baseUrl.trim(),
				model: model.trim(),
				min_confidence: parseFloat(minConf),
				timeout: parseInt(timeout, 10),
			};
			if (apiKey) body.api_key = apiKey;
			if (clearKey) body.clear_api_key = true;
			const r = await apiPost<{ ok: boolean; persisted: boolean; error?: string }>("/api/ai-config", body);
			status = r.persisted ? "✅ Tersimpan & berlaku langsung." : "✅ Diterapkan (file config tak ditulis).";
			toast("Pengaturan AI tersimpan");
			await load();
		} catch (e) {
			status = "❌ " + (e instanceof Error ? e.message : "gagal");
		} finally {
			saving = false;
		}
	}

	async function testConn() {
		testing = true;
		status = "menghubungi…";
		try {
			const r = await apiGet<{ ok: boolean; model?: string; latency_ms?: number; error?: string }>("/api/agent/test");
			status = r.ok ? `✅ OK — ${r.model} (${r.latency_ms} ms)` : `❌ Gagal: ${r.error}`;
		} catch (e) {
			status = "❌ " + (e instanceof Error ? e.message : "gagal");
		} finally {
			testing = false;
		}
	}

	function doLogout() {
		apiPost("/api/logout").catch(() => {});
		clearToken();
		try {
			sessionStorage.removeItem("perisai_user");
		} catch {
			/* abaikan */
		}
		markAuthed(false);
	}

	onMount(() => {
		load();
		loadSystemOne();
	});
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold">Setting</h1>
		<p class="text-sm text-muted-foreground">Pengaturan AI agent & sesi</p>
	</div>

	<Card class="max-w-3xl">
		<CardHeader>
			<CardTitle>⚙️ Setting AI Agent</CardTitle>
			<CardDescription>
				Endpoint OpenAI-compatible (mis. 9Router, Ollama, OpenAI). Perubahan berlaku langsung tanpa restart.
				API key tidak pernah ditampilkan kembali — kosongkan bila tidak ingin mengubahnya.
			</CardDescription>
		</CardHeader>
		<CardContent class="space-y-4">
			<div class="space-y-2">
				<Label>Backend</Label>
				<Select type="single" bind:value={backend}>
					<SelectTrigger><SelectValue /></SelectTrigger>
					<SelectContent>
						<SelectItem value="auto">auto — systemone → llm → heuristic</SelectItem>
						<SelectItem value="systemone">systemone — keputusan cepat via /v1/systemone</SelectItem>
						<SelectItem value="llm">llm — selalu pakai LLM</SelectItem>
						<SelectItem value="heuristic">heuristic — tanpa model jauh (offline)</SelectItem>
					</SelectContent>
				</Select>
			</div>
			<div class="space-y-2">
				<Label for="ai-base">Endpoint (OpenAI-compatible)</Label>
				<Input id="ai-base" bind:value={baseUrl} placeholder="https://9router.com/v1" />
			</div>
			<div class="space-y-2">
				<Label for="ai-key">API key</Label>
				<Input id="ai-key" type="password" bind:value={apiKey} placeholder="kosongkan = tidak diubah" autocomplete="off" />
				<label class="flex items-center gap-2 text-sm text-muted-foreground">
					<Switch bind:checked={clearKey} /> hapus key yang tersimpan
				</label>
				<p class="text-xs text-muted-foreground">{keySetHint}</p>
			</div>
			<div class="space-y-2">
				<Label for="ai-model">Model</Label>
				<div class="flex gap-2">
					<div class="relative flex-1">
						<Input
							id="ai-model"
							bind:value={model}
							placeholder="ketik untuk cari, atau isi manual…"
							autocomplete="off"
							onfocus={() => { modelSearch = model; showModelList = models.length > 0; }}
							oninput={(e) => { modelSearch = (e.target as HTMLInputElement).value; showModelList = true; }}
							onblur={() => setTimeout(() => (showModelList = false), 150)}
						/>
						{#if showModelList}
							<div class="absolute inset-x-0 top-full z-20 mt-1 max-h-56 overflow-auto rounded-md border border-border bg-popover shadow-lg">
								{#each filteredModels as m (m.id)}
									<button
										class="flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-accent"
										onmousedown={(e) => { e.preventDefault(); pickModel(m.id); }}
									>
										<span>{m.id}</span>
										{#if m.owned_by}<span class="text-xs text-muted-foreground">{m.owned_by}</span>{/if}
									</button>
								{/each}
								{#if model.trim() && !filteredModels.some((m) => m.id === model.trim())}
									<button
										class="w-full px-3 py-2 text-left text-sm hover:bg-accent"
										onmousedown={(e) => { e.preventDefault(); pickModel(model.trim()); }}
									>
										pakai "<b>{model.trim()}</b>"
									</button>
								{/if}
								{#if !filteredModels.length && !model.trim()}
									<div class="px-3 py-2 text-sm text-muted-foreground">(belum ada daftar — klik "🔄 Ambil daftar model")</div>
								{/if}
							</div>
						{/if}
					</div>
					<Button variant="outline" onclick={fetchModels} disabled={fetchingModels}>
						{fetchingModels ? "…" : "🔄 Ambil daftar model"}
					</Button>
				</div>
			</div>
			<div class="grid grid-cols-2 gap-4">
				<div class="space-y-2">
					<Label for="ai-minconf">Min confidence</Label>
					<Input id="ai-minconf" type="number" min="0" max="1" step="0.05" bind:value={minConf} />
				</div>
				<div class="space-y-2">
					<Label for="ai-timeout">Timeout LLM (detik)</Label>
					<Input id="ai-timeout" type="number" min="5" max="120" step="1" bind:value={timeout} />
				</div>
			</div>
			<div class="flex items-center gap-2">
				<Button onclick={save} disabled={saving}>{saving ? "Menyimpan…" : "💾 Simpan"}</Button>
				<Button variant="outline" onclick={testConn} disabled={testing}>🔌 Test koneksi</Button>
				{#if status}<span class="text-sm text-muted-foreground">{status}</span>{/if}
			</div>
		</CardContent>
	</Card>

	<Card class="max-w-3xl">
		<CardHeader>
			<CardTitle>🧠 System One</CardTitle>
			<CardDescription>
				Keputusan cepat non-autoregresif via protokol <code>/v1/systemone</code> (Noul: probabilitas
				request = serangan). Dipakai untuk triase trafik abu-abu — berlaku langsung tanpa restart.
				API key tidak pernah ditampilkan kembali.
			</CardDescription>
		</CardHeader>
		<CardContent class="space-y-4">
			<label class="flex items-center gap-2 text-sm">
				<Switch bind:checked={s1Enabled} /> aktifkan backend System One
			</label>
			<div class="space-y-2">
				<Label for="s1-endpoint">Endpoint</Label>
				<Input id="s1-endpoint" bind:value={s1Endpoint} placeholder="https://ai.skyzo.biz.id/v1/systemone" />
			</div>
			<div class="space-y-2">
				<Label for="s1-key">API key</Label>
				<Input id="s1-key" type="password" bind:value={s1ApiKey} placeholder="kosongkan = tidak diubah" autocomplete="off" />
				<label class="flex items-center gap-2 text-sm text-muted-foreground">
					<Switch bind:checked={s1ClearKey} /> hapus key yang tersimpan
				</label>
				<p class="text-xs text-muted-foreground">{s1KeySetHint}</p>
			</div>
			<div class="grid grid-cols-2 gap-4">
				<div class="space-y-2">
					<Label for="s1-model">Model</Label>
					<Input id="s1-model" bind:value={s1Model} placeholder="oc/jev-1.13-free" />
				</div>
				<div class="space-y-2">
					<Label for="s1-timeout">Timeout (detik)</Label>
					<Input id="s1-timeout" type="number" min="5" max="120" step="1" bind:value={s1Timeout} />
				</div>
			</div>
			<div class="flex items-center gap-2">
				<Button onclick={saveSystemOne} disabled={s1Saving}>{s1Saving ? "Menyimpan…" : "💾 Simpan"}</Button>
				<Button variant="outline" onclick={testSystemOne} disabled={s1Testing}>🔌 Test koneksi</Button>
				{#if s1Status}<span class="text-sm text-muted-foreground">{s1Status}</span>{/if}
			</div>
		</CardContent>
	</Card>

	<Card class="max-w-3xl">
		<CardHeader>
			<CardTitle>Sesi</CardTitle>
			<CardDescription>Token sesi tersimpan di browser ini (berlaku 12 jam)</CardDescription>
		</CardHeader>
		<CardContent>
			<div class="flex items-center justify-between">
				<code class="rounded bg-input px-2 py-1 font-mono text-xs">
					{getToken() ? getToken().slice(0, 12) + "…" : "(tidak ada)"}
				</code>
				<Button variant="destructive" onclick={doLogout}>Keluar</Button>
			</div>
		</CardContent>
	</Card>
</div>
