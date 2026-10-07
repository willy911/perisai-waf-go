<script lang="ts">
	import { Tabs } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: Tabs.ListProps = $props();
</script>

<Tabs.List
	bind:ref
	data-slot="tabs-list"
	class={cn(
		"inline-flex h-9 items-center justify-center rounded-lg bg-muted p-1 text-muted-foreground",
		className,
	)}
	{...restProps}
/>
