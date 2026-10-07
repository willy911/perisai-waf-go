<script lang="ts">
	import { DropdownMenu } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		inset = false,
		...restProps
	}: DropdownMenu.ItemProps & { inset?: boolean } = $props();
</script>

<DropdownMenu.Item
	bind:ref
	data-slot="dropdown-menu-item"
	data-inset={inset}
	class={cn(
		"relative flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none transition-colors focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
		inset && "pl-8",
		className,
	)}
	{...restProps}
/>
