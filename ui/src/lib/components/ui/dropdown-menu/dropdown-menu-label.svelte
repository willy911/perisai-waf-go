<script lang="ts">
	import { cn } from "$lib/utils.js";
	import type { Snippet } from "svelte";

	let {
		ref = $bindable(null),
		class: className,
		inset = false,
		children,
		...restProps
	}: {
		ref?: HTMLElement | null;
		class?: string;
		inset?: boolean;
		children?: Snippet;
		[key: string]: unknown;
	} = $props();
</script>

<div
	bind:this={ref}
	data-slot="dropdown-menu-label"
	data-inset={inset}
	class={cn("px-2 py-1.5 text-xs font-semibold text-muted-foreground", inset && "pl-8", className)}
	{...restProps}
>
	{@render children?.()}
</div>
