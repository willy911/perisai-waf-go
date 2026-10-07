<script lang="ts">
	import { toasts, dismissToast } from "$lib/stores.js";
	import { cn } from "$lib/utils.js";
	import { X, CheckCircle2, AlertTriangle } from "lucide-svelte";
</script>

<div class="fixed bottom-4 right-4 z-[100] flex w-[380px] max-w-[calc(100vw-2rem)] flex-col gap-2">
	{#each $toasts as t (t.id)}
		<div
			class={cn(
				"rounded-lg border bg-card p-4 shadow-lg",
				t.variant === "destructive" ? "border-destructive/50" : "border-border",
			)}
		>
			<div class="flex items-start gap-3">
				{#if t.variant === "destructive"}
					<AlertTriangle class="size-5 shrink-0 text-destructive" />
				{:else}
					<CheckCircle2 class="size-5 shrink-0 text-green-400" />
				{/if}
				<div class="flex-1">
					<div class="text-sm font-semibold">{t.title}</div>
					{#if t.description}
						<div class="mt-1 text-sm text-muted-foreground">{t.description}</div>
					{/if}
				</div>
				<button
					class="rounded-sm opacity-70 transition-opacity hover:opacity-100"
					onclick={() => dismissToast(t.id)}
					aria-label="Tutup"
				>
					<X class="size-4" />
				</button>
			</div>
		</div>
	{/each}
</div>
