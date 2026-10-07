<script lang="ts">
	import { onMount } from "svelte";
	import { apiGet } from "$lib/api.js";
	import type { AttackPoint } from "$lib/types.js";
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { RefreshCw } from "lucide-svelte";

	let canvas: HTMLCanvasElement;
	let info = $state("memuat…");
	let loading = $state(false);

	// Decode minimal TopoJSON (arcs delta-encoded) -> GeoJSON MultiPolygon.
	function topoToLand(topo: {
		transform: { scale: number[]; translate: number[] };
		arcs: number[][][];
		objects: { land: { geometries: { type: string; arcs: number[] }[] } };
	}): number[][][][] {
		const t = topo.transform.scale;
		const tr = topo.transform.translate;
		const arcs = topo.arcs.map((arc) => {
			let x = 0;
			let y = 0;
			return arc.map(([dx, dy]) => {
				x += dx;
				y += dy;
				return [x * t[0] + tr[0], y * t[1] + tr[1]];
			});
		});
		const one = (i: number) => (i >= 0 ? arcs[i] : arcs[~i].slice().reverse());
		const polys: number[][][][] = [];
		for (const g of topo.objects.land.geometries) {
			const pp = g.type === "Polygon" ? [g.arcs] : (g.arcs as unknown as number[][][]);
			for (const polyRings of pp as number[][][]) {
				polys.push((polyRings as unknown as number[][]).map((ids) => (ids as unknown as number[]).flatMap(one)));
			}
		}
		return polys;
	}

	async function drawMap() {
		const ctx = canvas.getContext("2d");
		if (!ctx) return;
		const W = canvas.width;
		const H = canvas.height;
		loading = true;
		ctx.clearRect(0, 0, W, H);
		info = "memuat…";
		let pts: AttackPoint[] = [];
		try {
			pts = await apiGet<AttackPoint[]>("/api/attack-map?hours=24");
		} catch {
			info = "gagal memuat data serangan";
			loading = false;
			return;
		}
		const proj = (lat: number, lon: number): [number, number] => [
			((lon + 180) / 360) * W,
			((90 - lat) / 180) * H,
		];
		try {
			const topo = (await (await fetch("map-land.json")).json()) as Parameters<typeof topoToLand>[0];
			const polys = topoToLand(topo);
			ctx.fillStyle = "#16233a";
			ctx.strokeStyle = "#334155";
			ctx.lineWidth = 0.7;
			ctx.beginPath();
			for (const poly of polys) {
				for (const ring of poly) {
					ring.forEach(([lo, la], i) => {
						const [x, y] = proj(la, lo);
						if (i) ctx.lineTo(x, y);
						else ctx.moveTo(x, y);
					});
					ctx.closePath();
				}
			}
			ctx.fill();
			ctx.stroke();
		} catch {
			ctx.strokeStyle = "#1e293b";
			for (let i = 1; i < 12; i++) {
				ctx.beginPath();
				ctx.moveTo((W * i) / 12, 0);
				ctx.lineTo((W * i) / 12, H);
				ctx.stroke();
			}
			for (let i = 1; i < 6; i++) {
				ctx.beginPath();
				ctx.moveTo(0, (H * i) / 6);
				ctx.lineTo(W, (H * i) / 6);
				ctx.stroke();
			}
		}
		if (!pts.length) {
			info = "belum ada serangan dari IP publik (IP privat tidak dipetakan)";
			loading = false;
			return;
		}
		const max = Math.max(1, ...pts.map((p) => p.count));
		for (const p of pts) {
			const [x, y] = proj(p.lat, p.lon);
			const r = 4 + 9 * Math.sqrt(p.count / max);
			const grd = ctx.createRadialGradient(x, y, 0, x, y, r * 2);
			grd.addColorStop(0, "rgba(239,68,68,.95)");
			grd.addColorStop(1, "rgba(239,68,68,0)");
			ctx.fillStyle = grd;
			ctx.beginPath();
			ctx.arc(x, y, r * 2, 0, 7);
			ctx.fill();
			ctx.fillStyle = "#e2e8f0";
			ctx.font = "11px sans-serif";
			ctx.fillText(`${p.city ? p.city + ", " : ""}${p.country} (${p.count}x)`, x + 8, y - 8);
		}
		const total = pts.reduce((a, p) => a + p.count, 0);
		info = `${pts.length} lokasi · ${total} serangan diblokir (24 jam)`;
		loading = false;
	}

	onMount(() => {
		drawMap();
	});
</script>

<Card>
	<CardHeader class="flex flex-row items-center justify-between">
		<div>
			<CardTitle>🗺️ Peta serangan</CardTitle>
			<CardDescription>{info}</CardDescription>
		</div>
		<Button variant="outline" size="sm" onclick={drawMap} disabled={loading}>
			<RefreshCw class="size-4 {loading ? 'animate-spin' : ''}" />
			Muat ulang
		</Button>
	</CardHeader>
	<CardContent>
		<canvas bind:this={canvas} width="1100" height="480" class="w-full rounded-xl border border-border bg-[#0b1220]"></canvas>
		<p class="mt-2 text-xs text-muted-foreground">
			GeoIP: file GeoLite2-City.mmdb di data_dir bila ada, else API ip-api.com (di-cache). IP privat tidak dipetakan.
		</p>
	</CardContent>
</Card>
