import { cn } from "$lib/utils.js";

export type BadgeVariant = "default" | "secondary" | "destructive" | "outline" | "success" | "warning";

export function badgeVariants(
	opts: { variant?: BadgeVariant; class?: string } = {},
): string {
	const { variant = "default", class: cls = "" } = opts;
	const base =
		"inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none";
	const variants: Record<BadgeVariant, string> = {
		default: "border-transparent bg-primary text-primary-foreground shadow hover:bg-primary/80",
		secondary: "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
		destructive:
			"border-transparent bg-destructive text-destructive-foreground shadow hover:bg-destructive/80",
		outline: "text-foreground",
		success: "border-transparent bg-green-500/15 text-green-400",
		warning: "border-transparent bg-amber-500/15 text-amber-400",
	};
	return cn(base, variants[variant], cls);
}
