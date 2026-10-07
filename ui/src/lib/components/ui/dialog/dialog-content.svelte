<script lang="ts">
	import { Dialog } from "bits-ui";
	import { cn } from "$lib/utils.js";
	import { X } from "lucide-svelte";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: Dialog.ContentProps = $props();
</script>

<Dialog.Portal>
	<Dialog.Overlay class="fixed inset-0 z-50 bg-black/70" />
	<Dialog.Content
		bind:ref
		data-slot="dialog-content"
		class={cn(
			"fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4 border bg-card p-6 shadow-lg rounded-xl max-h-[90vh] overflow-auto",
			className,
		)}
		{...restProps}
	>
		{@render children?.()}
		<Dialog.Close
			class="absolute right-4 top-4 rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:outline-none"
		>
			<X class="size-4" />
			<span class="sr-only">Tutup</span>
		</Dialog.Close>
	</Dialog.Content>
</Dialog.Portal>
