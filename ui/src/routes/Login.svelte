<script lang="ts">
	import { Shield } from "lucide-svelte";
	import { setToken } from "$lib/api.js";
	import { markAuthed } from "$lib/stores.js";
	import { Button } from "$lib/components/ui/button/index.js";
	import { Input } from "$lib/components/ui/input/index.js";
	import { Label } from "$lib/components/ui/label/index.js";
	import {
		Card,
		CardHeader,
		CardTitle,
		CardDescription,
		CardContent,
	} from "$lib/components/ui/card/index.js";

	let { ondone }: { ondone: (username: string) => void } = $props();

	let username = $state("");
	let password = $state("");
	let loading = $state(false);
	let err = $state("");

	async function doLogin() {
		if (!username.trim() || !password) {
			err = "Isi username & password.";
			return;
		}
		loading = true;
		err = "";
		try {
			// fetch mentah (tanpa wrapper api) agar pesan error 401/429/503 asli
			const res = await fetch("/api/login", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ username: username.trim(), password }),
			});
			const r = (await res.json().catch(() => ({}))) as {
				ok?: boolean;
				token?: string;
				username?: string;
				error?: string;
			};
			if (res.ok && r.ok && r.token) {
				setToken(r.token);
				try {
					sessionStorage.setItem("perisai_user", r.username || username.trim());
				} catch {
					/* abaikan */
				}
				password = "";
				markAuthed(true);
				ondone(r.username || username.trim());
			} else {
				err = "❌ " + (r.error || "Gagal login.");
			}
		} catch {
			err = "❌ Tidak bisa menghubungi server.";
		} finally {
			loading = false;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-background p-4">
	<Card class="w-full max-w-sm">
		<CardHeader class="text-center">
			<div class="mx-auto mb-2 flex size-12 items-center justify-center rounded-xl bg-primary/15">
				<Shield class="size-6 text-primary" />
			</div>
			<CardTitle class="text-xl">Perisai WAF</CardTitle>
			<CardDescription>Masuk ke dashboard admin</CardDescription>
		</CardHeader>
		<CardContent class="space-y-4">
			<div class="space-y-2">
				<Label for="login-user">Username</Label>
				<Input
					id="login-user"
					bind:value={username}
					placeholder="username"
					autocomplete="username"
					onkeydown={(e) => e.key === "Enter" && doLogin()}
				/>
			</div>
			<div class="space-y-2">
				<Label for="login-pass">Password</Label>
				<Input
					id="login-pass"
					type="password"
					bind:value={password}
					placeholder="password"
					autocomplete="current-password"
					onkeydown={(e) => e.key === "Enter" && doLogin()}
				/>
			</div>
			{#if err}
				<div class="text-sm text-destructive">{err}</div>
			{/if}
			<Button class="w-full" onclick={doLogin} disabled={loading}>
				{loading ? "Memeriksa…" : "Masuk"}
			</Button>
			<p class="text-xs text-muted-foreground">
				Belum atur password? Di server jalankan:<br />
				<code class="rounded bg-input px-1">./perisai-setpassword --config config.yaml</code><br />
				<span class="opacity-75">(Docker: cukup isi INITIAL_PASSWORD di .env)</span>
			</p>
		</CardContent>
	</Card>
</div>
