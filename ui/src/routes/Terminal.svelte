<script lang="ts">
	import { onMount, onDestroy } from "svelte";
	import { Terminal } from "@xterm/xterm";
	import { FitAddon } from "@xterm/addon-fit";
	import "@xterm/xterm/css/xterm.css";
	import { apiGet, getToken } from "$lib/api.js";
	import { toast } from "$lib/stores.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { RotateCcw, PlugZap } from "lucide-svelte";

	type TermCfg = { enabled: boolean; shell: string; work_dir: string };

	let termEl = $state<HTMLDivElement | null>(null);
	let term: Terminal | null = null;
	let fit: FitAddon | null = null;
	let ws: WebSocket | null = null;
	let cfg = $state<TermCfg | null>(null);
	let connected = $state(false);
	let ro: ResizeObserver | null = null;

	function wsUrl(): string {
		const proto = location.protocol === "https:" ? "wss:" : "ws:";
		return `${proto}//${location.host}/api/terminal/ws?token=${encodeURIComponent(getToken())}`;
	}

	function sendResize() {
		if (!ws || ws.readyState !== WebSocket.OPEN || !term) return;
		ws.send(JSON.stringify({ t: "resize", cols: term.cols, rows: term.rows }));
	}

	function connect() {
		disconnect();
		if (!term || !termEl) return;
		term.clear();
		term.writeln("\x1b[36mMenghubungkan ke terminal server...\x1b[0m");
		const sock = new WebSocket(wsUrl());
		ws = sock;
		sock.onopen = () => {
			connected = true;
			fit?.fit();
			sendResize();
		};
		sock.onmessage = (ev) => {
			try {
				const m = JSON.parse(String(ev.data));
				if (m.t === "out" && typeof m.d === "string") term?.write(m.d);
			} catch {
				/* abaikan */
			}
		};
		sock.onclose = () => {
			connected = false;
			term?.writeln("\r\n\x1b[33mKoneksi terputus. Klik \"Sambung ulang\" untuk membuka sesi baru.\x1b[0m");
		};
		sock.onerror = () => {
			toast("Gagal membuka websocket terminal.", { variant: "destructive" });
		};
	}

	function disconnect() {
		if (ws) {
			try {
				ws.close();
			} catch {
				/* abaikan */
			}
			ws = null;
		}
		connected = false;
	}

	onMount(async () => {
		try {
			cfg = await apiGet<TermCfg>("/api/terminal/config");
		} catch (e) {
			toast("Gagal memuat konfigurasi terminal.", { variant: "destructive" });
			return;
		}
		if (!cfg.enabled) {
			toast("Menu Terminal dimatikan di konfigurasi server.", { variant: "destructive" });
			return;
		}
		term = new Terminal({
			theme: {
				background: "#0b0f14",
				foreground: "#e6edf3",
				cursor: "#58a6ff",
				selectionBackground: "#264f78",
			},
			fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
			fontSize: 13,
			cursorBlink: true,
			allowProposedApi: true,
		});
		fit = new FitAddon();
		term.loadAddon(fit);
		term.open(termEl!);
		fit.fit();
		term.onData((data) => {
			if (ws && ws.readyState === WebSocket.OPEN) {
				ws.send(JSON.stringify({ t: "in", d: data }));
			}
		});
		ro = new ResizeObserver(() => {
			fit?.fit();
			sendResize();
		});
		ro.observe(termEl!);
		connect();
	});

	onDestroy(() => {
		ro?.disconnect();
		disconnect();
		term?.dispose();
		term = null;
	});
</script>

<Card>
	<CardHeader class="flex flex-row items-center justify-between gap-2">
		<div>
			<CardTitle class="flex items-center gap-2">
				<PlugZap class="size-5" /> Terminal Server
			</CardTitle>
			<CardDescription>
				Shell interaktif langsung di server WAF — berjalan di folder
				<span class="font-mono">{cfg?.work_dir ?? "…"}</span>
				{#if cfg} <span class="text-muted-foreground">({cfg.shell})</span>{/if}
			</CardDescription>
		</div>
		<Button variant="outline" size="sm" onclick={connect} disabled={!cfg?.enabled}>
			<RotateCcw class="size-4" /> Sambung ulang
		</Button>
	</CardHeader>
	<CardContent>
		{#if cfg && !cfg.enabled}
			<p class="text-sm text-muted-foreground">
				Terminal dimatikan. Aktifkan via <span class="font-mono">terminal.enabled: true</span> di config.yaml.
			</p>
		{:else}
			<div
				bind:this={termEl}
				class="h-[60vh] min-h-[380px] overflow-hidden rounded-md border bg-[#0b0f14] p-2"
			></div>
			<p class="mt-2 text-xs text-muted-foreground">
				Status: {connected ? "🟢 terhubung" : "🔴 terputus"} — semua perintah dicatat di log server untuk audit.
			</p>
		{/if}
	</CardContent>
</Card>
