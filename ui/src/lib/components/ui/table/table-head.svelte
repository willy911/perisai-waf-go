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

<th bind:this={ref} data-slot="table-head" class={cn("h-10 px-4 text-left align-middle text-xs font-semibold uppercase text-muted-foreground", className)} {...restProps}>
	{@render children?.()}
</th>
