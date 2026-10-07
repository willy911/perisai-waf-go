<script lang="ts">
	import { Tabs } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: Tabs.ContentProps = $props();
</script>

<Tabs.Content
	bind:ref
	data-slot="tabs-content"
	class={cn("mt-2 ring-offset-background focus-visible:outline-none", className)}
	{...restProps}
/>
