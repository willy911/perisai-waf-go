<script lang="ts">
	import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "$lib/components/ui/card/index.js";
	import type { WafRequest } from "$lib/types.js";

	let { requests }: { requests: WafRequest[] } = $props();

	interface Bucket {
		label: string;
		total: number;
		block: number;
	}

	function buckets(): Bucket[] {
		const now = Date.now();
		const out: Bucket[] = [];
		for (let i = 23; i >= 0; i--) {
			const start = now - (i + 1) * 3600_000;
			const end = now - i * 3600_000;
			const inHour = requests.filter((r) => r.ts * 1000 >= start && r.ts * 1000 < end);
			const block = inHour.filter((r) => r.decision === "block" || r.decision === "rate_limited").length;
			out.push({
				label: new Date(end).toLocaleTimeString("id-ID", { hour: "2-digit" }),
				total: inHour.length,
				block,
			});
		}
		return out;
	}

	const W = 720;
	const H = 160;
	const PAD = 8;

	let data = $derived(buckets());
	let max = $derived(Math.max(1, ...data.map((b) => b.total)));
	let bw = $derived((W - PAD * 2) / data.length);
</script>

<Card>
	<CardHeader>
		<CardTitle>Tren request (24 jam)</CardTitle>
		<CardDescription>Dari log permintaan terakhir · oranye = block/rate-limited</CardDescription>
	</CardHeader>
	<CardContent>
		<svg viewBox="0 0 {W} {H}" class="w-full">
			{#each data as b, i (i)}
				{@const h = Math.max(2, ((H - 30 - PAD) * b.total) / max)}
				{@const bh = Math.max(0, ((H - 30 - PAD) * b.block) / max)}
				<rect
					x={PAD + i * bw + 1}
					y={H - 22 - h}
					width={Math.max(1, bw - 2)}
					height={h}
					rx="2"
					class="fill-primary/70"
				>
					<title>{b.label}:00 — {b.total} request ({b.block} block)</title>
				</rect>
				{#if bh > 0}
					<rect
						x={PAD + i * bw + 1}
						y={H - 22 - bh}
						width={Math.max(1, bw - 2)}
						height={bh}
						rx="2"
						class="fill-amber-500"
					/>
				{/if}
				{#if i % 4 === 0}
					<text x={PAD + i * bw} y={H - 8} font-size="9" class="fill-muted-foreground">{b.label}</text>
				{/if}
			{/each}
		</svg>
	</CardContent>
</Card>
