<script lang="ts">
	import { Tabs } from "bits-ui";

	let { value = $bindable(""), ...restProps }: Tabs.RootProps = $props();
</script>

<Tabs.Root bind:value data-slot="tabs" {...restProps} />
