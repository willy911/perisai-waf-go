<script lang="ts">
	import { Select } from "bits-ui";

	// Wrapper ini hanya untuk single-select (kebutuhan dashboard).
	type SingleRootProps = Extract<Select.RootProps, { type: "single" }>;

	let { value = $bindable(""), type: _type, ...restProps }: SingleRootProps = $props();
</script>

<Select.Root type="single" bind:value {...restProps} />
