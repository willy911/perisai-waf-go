<script lang="ts">
	import { DropdownMenu } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: DropdownMenu.SeparatorProps = $props();
</script>

<DropdownMenu.Separator bind:ref data-slot="dropdown-menu-separator" class={cn("-mx-1 my-1 h-px bg-border", className)} {...restProps} />
