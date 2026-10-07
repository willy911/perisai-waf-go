<script lang="ts">
	import { Label } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: Label.RootProps = $props();
</script>

<Label.Root
	bind:ref
	data-slot="label"
	class={cn("text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70", className)}
	{...restProps}
/>
