<script lang="ts">
	import { Dialog } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: Dialog.DescriptionProps = $props();
</script>

<Dialog.Description bind:ref data-slot="dialog-description" class={cn("text-sm text-muted-foreground", className)} {...restProps} />
