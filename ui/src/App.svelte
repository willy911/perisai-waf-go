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

	// Susunan menu meniru struktur SafeLine: item utama (Dashboard,
	// Events) + grup Sites / Protections / System dengan sub-item.
	type MenuItem = { id: RouteName; label: string; icon: typeof LayoutDashboard };

	const TOP_MENU: MenuItem[] = [
		{ id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
		{ id: "logs", label: "Events", icon: Radar },
	];

	const MENU_GROUPS: { label: string; icon: typeof LayoutDashboard; items: MenuItem[] }[] = [
		{
			label: "Sites",
			icon: Globe,
			items: [{ id: "website", label: "Website", icon: Globe }],
		},
		{
			label: "Protections",
			icon: ShieldCheck,
			items: [
				{ id: "iplist", label: "Black/whitelist IP", icon: ShieldX },
				{ id: "rules", label: "Custom rule", icon: Braces },
				{ id: "recaptcha", label: "ReCAPTCHA", icon: ShieldCheck },
				{ id: "cache", label: "Cache", icon: Database },
				{ id: "ipgroup", label: "IP Group", icon: Network },
			],
		},
		{
			label: "System",
			icon: Settings,
			items: [
				{ id: "terminal", label: "Terminal", icon: SquareTerminal },
				{ id: "setting", label: "Setting", icon: Settings },
			],
		},
	];

	const LABELS: Record<string, string> = Object.fromEntries(
		[...TOP_MENU, ...MENU_GROUPS.flatMap((g) => g.items)].map((m) => [m.id, m.label]),
	);

	let currentLabel = $derived(LABELS[$route] ?? "Dashboard");

	let username = $state("");

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
		<aside class="fixed inset-y-0 left-0 z-40 flex w-64 flex-col bg-card shadow-[1px_0_0_0_var(--border)]">
			<div class="flex h-[72px] items-center gap-2.5 px-6">
				<span class="flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-lg shadow-primary/30">
					<Shield class="size-5" />
				</span>
				<span class="text-[17px] font-extrabold tracking-tight">Perisai <span class="text-primary">WAF</span></span>
			</div>
			<nav class="flex-1 overflow-y-auto px-4 pb-4">
				{#each TOP_MENU as m (m.id)}
					{@const Icon = m.icon}
					<button
						onclick={() => navigate(m.id)}
						class={cn(
							"mb-1 flex w-full items-center gap-3 rounded-xl px-4 py-3 text-sm font-semibold transition-all",
							$route === m.id
								? "bg-primary text-primary-foreground shadow-lg shadow-primary/30"
								: "text-foreground/70 hover:bg-accent hover:text-accent-foreground",
						)}
					>
						<Icon class="size-[18px] shrink-0" />
						{m.label}
					</button>
				{/each}
				{#each MENU_GROUPS as g (g.label)}
					{@const GIcon = g.icon}
					<div class="pt-4">
						<div class="flex items-center gap-3 px-4 py-2 text-sm font-semibold text-foreground/80">
							<GIcon class="size-[18px] shrink-0" />
							{g.label}
						</div>
						<div class="space-y-0.5">
							{#each g.items as m (m.id)}
								<button
									onclick={() => navigate(m.id)}
									class={cn(
										"ml-4 flex w-[calc(100%-1rem)] items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
										$route === m.id
											? "bg-primary/10 font-bold text-primary"
											: "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
									)}
								>
									<span class={cn(
										"size-1.5 shrink-0 rounded-full",
										$route === m.id ? "bg-primary" : "bg-muted-foreground/40",
									)}></span>
									{m.label}
								</button>
							{/each}
						</div>
					</div>
				{/each}
			</nav>
			<div class="p-4">
				{#if username}
					<div class="mb-2 flex items-center gap-2 rounded-full bg-muted px-3.5 py-2 text-xs font-semibold">
						<span class="size-2 shrink-0 rounded-full bg-emerald-500"></span>
						<span class="truncate">{username}</span>
					</div>
				{/if}
				<Button variant="ghost" class="w-full justify-start rounded-xl" onclick={doLogout}>
					<LogOut class="size-4" />
					Keluar
				</Button>
			</div>
		</aside>
		<main class="ml-64 flex-1 px-6 py-5 lg:px-8">
			<div class="mx-auto max-w-[1440px]">
				<header class="mb-6 flex items-center justify-between">
					<div class="text-[15px] text-muted-foreground">
						Perisai <span class="mx-1 text-border">/</span>
						<span class="font-bold text-foreground">{currentLabel}</span>
					</div>
					<div class="flex items-center gap-3">
						<span class="hidden items-center gap-2 rounded-full bg-card px-3.5 py-1.5 text-xs font-semibold shadow-sm sm:flex">
							<span class="size-2 rounded-full bg-emerald-500"></span>
							WAF Aktif
						</span>
						<button
							onclick={doLogout}
							title="Keluar"
							class="flex size-9 items-center justify-center rounded-full bg-card shadow-sm transition-colors hover:text-destructive"
						>
							<LogOut class="size-4" />
						</button>
					</div>
				</header>
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
