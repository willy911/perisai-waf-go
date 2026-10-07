<script lang="ts">
	import { cn } from "$lib/utils.js";
	import type { Snippet } from "svelte";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: { ref?: HTMLElement | null; class?: string; children?: Snippet; [key: string]: unknown } = $props();
</script>

<tr bind:this={ref} data-slot="table-row" class={cn("border-b transition-colors hover:bg-muted/50", className)} {...restProps}>
	{@render children?.()}
</tr>
