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

<div bind:this={ref} data-slot="dialog-footer" class={cn("flex flex-col-reverse sm:flex-row sm:justify-end sm:gap-2", className)} {...restProps}>
	{@render children?.()}
</div>
