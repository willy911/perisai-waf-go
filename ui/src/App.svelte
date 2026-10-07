<script lang="ts">
	import { onMount } from "svelte";
	import {
		LayoutDashboard,
		Globe,
		Radar,
		ShieldX,
		Braces,
		ShieldCheck,
		Database,
		Network,
		Settings,
		LogOut,
		Shield,
		SquareTerminal,
	} from "lucide-svelte";
	import { route, authed, markAuthed, navigate, type RouteName } from "$lib/stores.js";
	import { getToken, clearToken, apiPost } from "$lib/api.js";
	import { cn } from "$lib/utils.js";
	import { Toaster } from "$lib/components/ui/sonner/index.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import Login from "./routes/Login.svelte";
	import Dashboard from "./routes/Dashboard.svelte";
	import Website from "./routes/Website.svelte";
	import Logs from "./routes/Logs.svelte";
	import IpList from "./routes/IpList.svelte";
	import Rules from "./routes/Rules.svelte";
	import Recaptcha from "./routes/Recaptcha.svelte";
	import Cache from "./routes/Cache.svelte";
	import IpGroup from "./routes/IpGroup.svelte";
	import Terminal from "./routes/Terminal.svelte";
	import SettingsPage from "./routes/Settings.svelte";

	const MENU: { id: RouteName; label: string; icon: typeof LayoutDashboard }[] = [
		{ id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
		{ id: "website", label: "Website", icon: Globe },
		{ id: "logs", label: "Interceptions logs", icon: Radar },
		{ id: "iplist", label: "Black/whitelist IP", icon: ShieldX },
		{ id: "rules", label: "Custom rule", icon: Braces },
		{ id: "recaptcha", label: "ReCAPTCHA", icon: ShieldCheck },
		{ id: "cache", label: "Cache", icon: Database },
		{ id: "ipgroup", label: "IP Group", icon: Network },
		{ id: "terminal", label: "Terminal", icon: SquareTerminal },
		{ id: "setting", label: "Setting", icon: Settings },
	];

	let username = "";

	onMount(() => {
		markAuthed(!!getToken());
		try {
			username = sessionStorage.getItem("perisai_user") || "";
		} catch {
			/* abaikan */
		}
		const onUnauth = () => markAuthed(false);
		window.addEventListener("perisai:unauthorized", onUnauth);
		return () => window.removeEventListener("perisai:unauthorized", onUnauth);
	});

	async function doLogout() {
		try {
			await apiPost("/api/logout");
		} catch {
			/* abaikan */
		}
		clearToken();
		try {
			sessionStorage.removeItem("perisai_user");
		} catch {
			/* abaikan */
		}
		username = "";
		markAuthed(false);
	}
</script>

{#if !$authed}
	<Login ondone={(u) => { username = u; }} />
{:else}
	<div class="flex min-h-screen bg-background text-foreground">
		<aside class="fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-border bg-card">
			<div class="flex h-16 items-center gap-2 border-b border-border px-5">
				<Shield class="size-6 text-primary" />
				<span class="text-lg font-bold">Perisai <span class="text-primary">WAF</span></span>
			</div>
			<nav class="flex-1 space-y-1 overflow-y-auto p-3">
				{#each MENU as m (m.id)}
					{@const Icon = m.icon}
					<button
						onclick={() => navigate(m.id)}
						class={cn(
							"flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
							$route === m.id
								? "bg-primary text-primary-foreground"
								: "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
						)}
					>
						<Icon class="size-4 shrink-0" />
						{m.label}
					</button>
				{/each}
			</nav>
			<div class="border-t border-border p-3">
				{#if username}
					<div class="mb-2 px-3 text-xs text-muted-foreground">👤 {username}</div>
				{/if}
				<Button variant="ghost" class="w-full justify-start" onclick={doLogout}>
					<LogOut class="size-4" />
					Keluar
				</Button>
			</div>
		</aside>
		<main class="ml-60 flex-1 p-6">
			<div class="mx-auto max-w-6xl">
				{#if $route === "dashboard"}<Dashboard />
				{:else if $route === "website"}<Website />
				{:else if $route === "logs"}<Logs />
				{:else if $route === "iplist"}<IpList />
				{:else if $route === "rules"}<Rules />
				{:else if $route === "recaptcha"}<Recaptcha />
				{:else if $route === "cache"}<Cache />
				{:else if $route === "ipgroup"}<IpGroup />
				{:else if $route === "terminal"}<Terminal />
				{:else if $route === "setting"}<SettingsPage />
				{/if}
			</div>
		</main>
	</div>
{/if}
<Toaster />
