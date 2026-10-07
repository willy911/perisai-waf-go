<script lang="ts">
	import { Select } from "bits-ui";
	import { cn } from "$lib/utils.js";
	import { ChevronDown } from "lucide-svelte";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: Select.TriggerProps = $props();
</script>

<Select.Trigger
	bind:ref
	data-slot="select-trigger"
	class={cn(
		"flex h-9 w-full items-center justify-between whitespace-nowrap rounded-md border border-input bg-input px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50 [&>span]:line-clamp-1",
		className,
	)}
	{...restProps}
>
	{@render children?.()}
	<ChevronDown class="size-4 opacity-50" />
</Select.Trigger>
