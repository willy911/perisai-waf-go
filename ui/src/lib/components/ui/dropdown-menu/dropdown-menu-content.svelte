<script lang="ts">
	import { DropdownMenu } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: DropdownMenu.ContentProps = $props();
</script>

<DropdownMenu.Portal>
	<DropdownMenu.Content
		bind:ref
		data-slot="dropdown-menu-content"
		class={cn(
			"z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md",
			className,
		)}
		{...restProps}
	/>
</DropdownMenu.Portal>
