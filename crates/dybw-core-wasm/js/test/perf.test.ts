// Timings of the WASM build, printed as a table (information), with the plugin's budgets: PBKDF2 at 600 000
// iterations under 3 000 ms, and the planner alone over 10 000 secrets (`plan-10000`) under 500 ms.
// `decrypt-1000-of-5000` scans 5 000 ciphers of which 1 000 carry the marker.
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

test("times PBKDF2, the vault scan and the planner", async () => {
  const files = new Map(Object.entries(inject("files")));
  const ports = { ...hostPorts(), nowMs: () => performance.now() };
  const report = JSON.parse(await runPerf(files, ports)) as Perf;
  expect(report.results.map(([name, , error]) => [name, error])).toEqual([
    ["pbkdf2-600k", null],
    ["decrypt-1000-of-5000", null],
    ["plan-10000", null],
  ]);
  console.log(["| engine | timing | ms |", ...report.results.map(([n, ms]) => `| ${engine} | ${n} | ${ms} |`)].join("\n"));
  const ms = (name: string) => report.results.find(([n]) => n === name)?.[1];
  expect(ms("pbkdf2-600k")).toBeLessThan(3_000);
  expect(ms("plan-10000")).toBeLessThan(500);
});
