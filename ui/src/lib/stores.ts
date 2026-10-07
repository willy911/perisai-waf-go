import { writable } from "svelte/store";

// ---- routing (hash-based) ----
export type RouteName =
	| "dashboard"
	| "website"
	| "logs"
	| "iplist"
	| "rules"
	| "recaptcha"
	| "cache"
	| "ipgroup"
	| "terminal"
	| "setting";

const VALID_ROUTES: RouteName[] = [
	"dashboard",
	"website",
	"logs",
	"iplist",
	"rules",
	"recaptcha",
	"cache",
	"ipgroup",
	"terminal",
	"setting",
];

function routeFromHash(): RouteName {
	const h = window.location.hash.replace(/^#\/?/, "").split("?")[0];
	return (VALID_ROUTES as string[]).includes(h) ? (h as RouteName) : "dashboard";
}

export const route = writable<RouteName>(routeFromHash());

export function navigate(r: RouteName) {
	window.location.hash = "#/" + r;
}

if (typeof window !== "undefined") {
	window.addEventListener("hashchange", () => route.set(routeFromHash()));
}

// ---- auth ----
export const authed = writable<boolean>(false);

export function markAuthed(v: boolean) {
	authed.set(v);
}

// ---- toast (sonner-style, ringan) ----
export interface Toast {
	id: number;
	title: string;
	description?: string;
	variant: "default" | "destructive";
}

export const toasts = writable<Toast[]>([]);
let toastSeq = 0;

export function toast(
	title: string,
	opts: { description?: string; variant?: "default" | "destructive" } = {},
) {
	const id = ++toastSeq;
	const t: Toast = {
		id,
		title,
		description: opts.description,
		variant: opts.variant ?? "default",
	};
	toasts.update((all) => [...all.slice(-4), t]);
	setTimeout(() => {
		toasts.update((all) => all.filter((x) => x.id !== id));
	}, 4500);
}

export function dismissToast(id: number) {
	toasts.update((all) => all.filter((x) => x.id !== id));
}
