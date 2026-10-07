<script lang="ts">
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		value = $bindable(),
		type = "text",
		class: className,
		onkeydown,
		onfocus,
		onblur,
		oninput,
		...restProps
	}: {
		ref?: HTMLInputElement | null;
		value?: string | number | null;
		type?: string;
		class?: string;
		onkeydown?: (e: KeyboardEvent) => void;
		onfocus?: (e: FocusEvent) => void;
		onblur?: (e: FocusEvent) => void;
		oninput?: (e: Event) => void;
		[key: string]: unknown;
	} = $props();
</script>

<input
	bind:this={ref}
	data-slot="input"
	{type}
	class={cn(
		"flex h-9 w-full rounded-md border border-input bg-input px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
		className,
	)}
	bind:value
	{onkeydown}
	{onfocus}
	{onblur}
	{oninput}
	{...restProps}
/>
