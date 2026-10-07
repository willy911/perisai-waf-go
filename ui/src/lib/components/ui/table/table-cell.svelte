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

<td bind:this={ref} data-slot="table-cell" class={cn("p-4 align-top", className)} {...restProps}>
	{@render children?.()}
</td>
