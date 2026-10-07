<script lang="ts">
	import { Select } from "bits-ui";
	import { cn } from "$lib/utils.js";
	import { Check } from "lucide-svelte";
	import type { Snippet } from "svelte";

	let {
		ref = $bindable(null),
		class: className,
		value,
		children,
		...restProps
	}: Omit<Select.ItemProps, "children" | "child"> & { children?: Snippet } = $props();
</script>

<Select.Item
	bind:ref
	{value}
	data-slot="select-item"
	class={cn(
		"relative flex w-full cursor-pointer select-none items-center rounded-sm py-1.5 pl-2 pr-8 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
		className,
	)}
	{...restProps}
>
	{#snippet child({ selected })}
		<span class="absolute right-2 flex size-3.5 items-center justify-center">
			{#if selected}
				<Check class="size-4" />
			{/if}
		</span>
		{@render children?.()}
	{/snippet}
</Select.Item>
