// The WASM build in Node, in Chromium (Obsidian Android's System WebView) and in WebKit (Obsidian iOS's WKWebView).
// Build it first: `scripts/build-wasm.sh --features vectors --out crates/dybw-core-wasm/js/pkg`.
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

const browser = (name: "chromium" | "webkit") => ({
  extends: true,
  test: {
    name,
    browser: { enabled: true, headless: true, provider: playwright(), instances: [{ browser: name }] },
  },
});

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    globalSetup: ["test/setup.ts"],
    testTimeout: 300_000,
    projects: [{ extends: true, test: { name: "node", environment: "node" } }, browser("chromium"), browser("webkit")],
  },
});
