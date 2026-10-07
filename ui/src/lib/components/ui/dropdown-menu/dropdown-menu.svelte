<script lang="ts">
	import { DropdownMenu } from "bits-ui";

	let { ...restProps }: DropdownMenu.RootProps = $props();
</script>

<DropdownMenu.Root {...restProps} />
