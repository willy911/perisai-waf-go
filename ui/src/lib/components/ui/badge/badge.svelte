<script lang="ts">
	import { cn } from "$lib/utils.js";
	import { badgeVariants, type BadgeVariant } from "./badge.js";
	import type { Snippet } from "svelte";

	let {
		ref = $bindable(null),
		variant = "default",
		class: className,
		children,
		...restProps
	}: {
		ref?: HTMLElement | null;
		variant?: BadgeVariant;
		class?: string;
		children?: Snippet;
		[key: string]: unknown;
	} = $props();
</script>

<span bind:this={ref} data-slot="badge" class={cn(badgeVariants({ variant }), className)} {...restProps}>
	{@render children?.()}
</span>
