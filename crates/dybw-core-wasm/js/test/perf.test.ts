// Timings of the WASM build, printed as a table (information), with one budget: PBKDF2 at 600 000 iterations under
// 3 000 ms, the plugin's. `decrypt-1000-of-5000` scans 5 000 ciphers of which 1 000 carry the marker.
import { beforeAll, expect, inject, test } from "vitest";
import init, { runPerf } from "../pkg/dybw_core_wasm.js";
import { hostPorts } from "./ports";

type Perf = { results: [string, number, string | null][] };

const agent = typeof navigator === "undefined" ? "" : navigator.userAgent;
const engine = /Chrome/.test(agent) ? "chromium" : /AppleWebKit/.test(agent) ? "webkit" : "node";

beforeAll(async () => {
  const wasm = Uint8Array.from(atob(inject("wasm")), (c) => c.charCodeAt(0));
  await init({ module_or_path: wasm });
});

test("times PBKDF2 and the vault scan", async () => {
  const files = new Map(Object.entries(inject("files")));
  const ports = { ...hostPorts(), nowMs: () => performance.now() };
  const report = JSON.parse(await runPerf(files, ports)) as Perf;
  expect(report.results.map(([name, , error]) => [name, error])).toEqual([
    ["pbkdf2-600k", null],
    ["decrypt-1000-of-5000", null],
  ]);
  console.log(["| engine | timing | ms |", ...report.results.map(([n, ms]) => `| ${engine} | ${n} | ${ms} |`)].join("\n"));
  const pbkdf2 = report.results.find(([n]) => n === "pbkdf2-600k")?.[1];
  expect(pbkdf2).toBeLessThan(3_000);
});
