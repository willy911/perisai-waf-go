<script lang="ts">
	import { Dialog } from "bits-ui";

	let { ...restProps }: Dialog.TriggerProps = $props();
</script>

<Dialog.Trigger {...restProps} />
