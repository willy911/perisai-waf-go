// Wrapper fetch untuk API Perisai WAF: otomatis menambahkan ?token=
// dari localStorage, dan melempar event "perisai:unauthorized" bila 401
// agar aplikasi kembali ke halaman login.

const TOKEN_KEY = "perisai_token";

export function getToken(): string {
	try {
		return localStorage.getItem(TOKEN_KEY) || "";
	} catch {
		return "";
	}
}

export function setToken(t: string) {
	try {
		localStorage.setItem(TOKEN_KEY, t);
	} catch {
		/* abaikan */
	}
}

export function clearToken() {
	try {
		localStorage.removeItem(TOKEN_KEY);
	} catch {
		/* abaikan */
	}
}

export class ApiError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = "ApiError";
		this.status = status;
	}
}

export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
	const token = getToken();
	const sep = path.includes("?") ? "&" : "?";
	const headers: Record<string, string> = {};
	if (opts.body !== undefined) headers["Content-Type"] = "application/json";
	for (const [k, v] of Object.entries(opts.headers || {})) {
		headers[k] = String(v);
	}
	const res = await fetch(path + sep + "token=" + encodeURIComponent(token), {
		...opts,
		headers,
	});
	if (res.status === 401) {
		clearToken();
		window.dispatchEvent(new CustomEvent("perisai:unauthorized"));
		throw new ApiError("Sesi kedaluwarsa, silakan login ulang.", 401);
	}
	let data: unknown = {};
	try {
		data = await res.json();
	} catch {
		/* bukan JSON */
	}
	if (!res.ok) {
		const msg =
			typeof data === "object" && data !== null && "error" in data
				? String((data as { error: unknown }).error)
				: `HTTP ${res.status}`;
		throw new ApiError(msg, res.status);
	}
	return data as T;
}

export const apiGet = <T>(path: string) => api<T>(path);

export const apiPost = <T>(path: string, body?: unknown) =>
	api<T>(path, {
		method: "POST",
		body: body === undefined ? undefined : JSON.stringify(body),
	});

export const apiPut = <T>(path: string, body?: unknown) =>
	api<T>(path, {
		method: "PUT",
		body: body === undefined ? undefined : JSON.stringify(body),
	});

export const apiDel = <T>(path: string, body?: unknown) =>
	api<T>(path, {
		method: "DELETE",
		body: body === undefined ? undefined : JSON.stringify(body),
	});
