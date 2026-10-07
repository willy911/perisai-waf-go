<script lang="ts">
	import { DropdownMenu } from "bits-ui";

	let { ...restProps }: DropdownMenu.TriggerProps = $props();
</script>

<DropdownMenu.Trigger {...restProps} />
