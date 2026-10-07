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

<p bind:this={ref} data-slot="card-description" class={cn("text-sm text-muted-foreground", className)} {...restProps}>
	{@render children?.()}
</p>
