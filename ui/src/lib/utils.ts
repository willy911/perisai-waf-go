import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
	return twMerge(clsx(inputs));
}

export function fmtTime(ts: number): string {
	if (!ts) return "-";
	return new Date(ts * 1000).toLocaleTimeString("id-ID");
}

export function fmtDateTime(ts: number): string {
	if (!ts) return "-";
	return new Date(ts * 1000).toLocaleString("id-ID");
}

export function fmtDate(ts: number): string {
	if (!ts) return "-";
	return new Date(ts * 1000).toLocaleDateString("id-ID", {
		day: "numeric",
		month: "short",
		year: "numeric",
	});
}

export function fmtBytes(n: number): string {
	if (!n) return "0 B";
	const u = ["B", "KB", "MB", "GB"];
	let i = 0;
	let v = n;
	while (v >= 1024 && i < u.length - 1) {
		v /= 1024;
		i++;
	}
	return `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}
