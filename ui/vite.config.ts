import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
import path from "node:path";

// Build: `npm run build` -> ./dist (disajikan server dashboard Python)
// Dev: `npm run dev` (proxy /api ke backend :8899)
export default defineConfig({
	base: "./",
	build: { outDir: "dist", emptyOutDir: true },
	plugins: [svelte(), tailwindcss()],
	resolve: {
		alias: {
			$lib: path.resolve(import.meta.dirname, "src/lib"),
		},
	},
	server: {
		port: 5173,
		proxy: {
			"/api": "http://127.0.0.1:8899",
			"/map-land.json": "http://127.0.0.1:8899",
		},
	},
});
