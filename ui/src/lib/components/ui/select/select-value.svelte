<script lang="ts">
	import { Select } from "bits-ui";

	let { ...restProps }: Select.ValueProps = $props();
</script>

<Select.Value placeholder="Pilih…" {...restProps} />
