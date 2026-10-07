<script lang="ts">
	import { cn } from "$lib/utils.js";
	import type { Snippet } from "svelte";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: {
		ref?: HTMLElement | null;
		class?: string;
		children?: Snippet;
		[key: string]: unknown;
	} = $props();
</script>

<div bind:this={ref} data-slot="card-title" class={cn("font-semibold leading-none tracking-tight", className)} {...restProps}>
	{@render children?.()}
</div>
