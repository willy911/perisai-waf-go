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

<div data-slot="table-container" class="relative w-full overflow-auto rounded-xl border bg-card">
	<table bind:this={ref} data-slot="table" class={cn("w-full caption-bottom text-sm", className)} {...restProps}>
		{@render children?.()}
	</table>
</div>
