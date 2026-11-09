// The size report of a build (D12): the module after wasm-opt, its base64 (`4·⌈n/3⌉`, how the plugin embeds it), the
// glue after esbuild minify (cjs, as the plugin bundles it), gzip of the module (information only), and the total
// against the budget. `node size.mjs <dir>` prints it.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { transformSync } from "esbuild";

/** Bytes for base64(wasm) + minified glue. */
export const BUDGET = 1_179_648;

export function sizeReport(dir) {
  const wasm = readFileSync(join(dir, "dybw_core_wasm_bg.wasm"));
  const glue = transformSync(readFileSync(join(dir, "dybw_core_wasm.js"), "utf8"), { format: "cjs", minify: true });
  const base64 = 4 * Math.ceil(wasm.length / 3);
  const glueBytes = Buffer.byteLength(glue.code);
  const gzip = gzipSync(wasm, { level: 9 }).length;
  return { wasm: wasm.length, base64, glue: glueBytes, gzip, total: base64 + glueBytes, budget: BUDGET };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const r = sizeReport(process.argv[2]);
  console.log(`wasm ${r.wasm} B, base64 ${r.base64} B, glue ${r.glue} B, gzip ${r.gzip} B (information)`);
  console.log(`total ${r.total} B of ${r.budget} B: ${r.total <= r.budget ? "within" : "OVER"} the budget`);
}
