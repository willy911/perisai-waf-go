<script lang="ts">
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		value = $bindable(),
		class: className,
		onkeydown,
		onfocus,
		onblur,
		oninput,
		...restProps
	}: {
		ref?: HTMLTextAreaElement | null;
		value?: string | null;
		class?: string;
		onkeydown?: (e: KeyboardEvent) => void;
		onfocus?: (e: FocusEvent) => void;
		onblur?: (e: FocusEvent) => void;
		oninput?: (e: Event) => void;
		[key: string]: unknown;
	} = $props();
</script>

<textarea
	bind:this={ref}
	data-slot="textarea"
	class={cn(
		"flex min-h-[60px] w-full rounded-md border border-input bg-input px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
		className,
	)}
	bind:value
	{onkeydown}
	{onfocus}
	{onblur}
	{oninput}
	{...restProps}
></textarea>
