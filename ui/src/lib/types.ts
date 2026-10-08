// Bentuk data API Perisai WAF (lihat docs/UI-API-CONTRACT.md +
// perisai/dashboard.py sebagai sumber kebenaran).

export interface StatsResponse {
	total: number;
	by_decision: Record<string, number>;
	top_rules: { rule: string; count: number }[];
	top_offenders: { ip: string; count: number }[];
	rules_loaded: number;
}

export interface WafRequest {
	id: string;
	ts: number;
	ip: string;
	method: string;
	path: string;
	query: string;
	score: number;
	decision: string;
	agent_conf: number;
	duration_ms: number;
	top_rule: string;
	site_id: string;
}

export interface AgentRun {
	ts: number;
	backend: string;
	decision: string;
	confidence: number;
	reasoning: string[];
	indicators: string[];
}

export interface ProposedRule {
	id: number;
	ts: number;
	rule: {
		id: string;
		name: string;
		category: string;
		severity: string;
		pattern: string;
	};
	note: string;
	source: string;
}

export interface BuiltinRule {
	id: string;
	name: string;
	category: string;
	severity: string;
	weight: number;
}

export interface IpEntry {
	id: string;
	network: string;
	list: "white" | "black";
	scope: string;
	note: string;
	expires_at: number;
}

export interface Site {
	id: string;
	domain: string;
	upstream_host: string;
	upstream_port: number;
	upstream_tls: number | boolean;
	upstream_tls_verify: number | boolean;
	preserve_host: number | boolean;
	enabled: number | boolean;
	agent_enabled: number | boolean;
	ddos_mode: number | boolean;
	ddos_rps: number;
	tls_cert: string;
	tls_key: string;
	tls_expires_at: number;
	requests_24h?: number;
	recaptcha_enabled?: number | boolean;
	blocked_countries?: string;
}

export interface AiConfig {
	backend: string;
	min_confidence: number;
	llm: {
		base_url: string;
		model: string;
		timeout: number;
		api_key_set: boolean;
	};
}

export interface SystemOneConfig {
	enabled: boolean;
	endpoint: string;
	model: string;
	timeout: number;
	api_key_set: boolean;
}

export interface ModelInfo {
	id: string;
	owned_by?: string;
}

export interface AttackPoint {
	ip: string;
	count: number;
	last_ts: number;
	country: string;
	city: string;
	lat: number;
	lon: number;
}

// ---- endpoint baru (kontrak UI-API-CONTRACT.md) ----

export interface CacheConfig {
	enabled: boolean;
	ttl: number;
	max_entries: number;
	max_object_kb: number;
	bypass_cookies: string[];
}

export interface CacheStats {
	hits: number;
	misses: number;
	hit_ratio: number;
	entries: number;
	bytes: number;
}

export interface IpGroup {
	id: string;
	name: string;
	kind: "white" | "black";
	description: string;
	members: string[];
	created_at: number;
}

export interface RecaptchaConfig {
	enabled: boolean;
	site_key: string;
	mode: "v2" | "v3";
	site_key_set: boolean;
}

export interface CfZone {
	site_id: string;
	zone_id: string;
	zone_name: string;
}

export interface CfConfig {
	api_token_set: boolean;
	zones: CfZone[];
}

export interface CfStats {
	requests: number;
	threats: number;
	cached_pct: number;
	bandwidth: number;
	updated_at: number;
}
