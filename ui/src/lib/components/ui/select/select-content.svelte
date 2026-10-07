<script lang="ts">
	import { Select } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: Select.ContentProps = $props();
</script>

<Select.Portal>
	<Select.Content
		bind:ref
		data-slot="select-content"
		class={cn(
			"relative z-50 max-h-96 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=closed]:animate-out",
			className,
		)}
		{...restProps}
	>
		<Select.Viewport class="p-1 max-h-[300px] overflow-auto">
			{@render children?.()}
		</Select.Viewport>
	</Select.Content>
</Select.Portal>
