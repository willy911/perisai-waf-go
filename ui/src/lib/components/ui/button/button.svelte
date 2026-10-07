<script lang="ts">
	import { Button } from "bits-ui";
	import { cn } from "$lib/utils.js";
	import {
		buttonVariants,
		type ButtonSize,
		type ButtonVariant,
	} from "./button.js";

	let {
		ref = $bindable(null),
		variant = "default",
		size = "default",
		class: className,
		...restProps
	}: Button.RootProps & {
		variant?: ButtonVariant;
		size?: ButtonSize;
	} = $props();
</script>

<Button.Root
	bind:ref
	data-slot="button"
	class={cn(buttonVariants({ variant, size }), className)}
	{...restProps}
/>
