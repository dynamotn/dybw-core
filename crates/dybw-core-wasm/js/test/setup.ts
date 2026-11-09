// Runs in Node before each project: reads the vector files, the expected failures and the WASM module, and hands
// them to the tests, which may run in a browser without a file system.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { TestProject } from "vitest/node";
// @ts-expect-error: a plain ES module without types.
import { sizeReport } from "../size.mjs";

declare module "vitest" {
  export interface ProvidedContext {
    /** `vectors/{generated,accounts,crypto}/**.json` by path relative to `vectors/`. */
    files: Record<string, string>;
    /** The vector ids `expected-failures.txt` lists. */
    expectedFailures: string[];
    /** The module after wasm-opt, as base64. */
    wasm: string;
    /** The size report of the build without `vectors` at `target-wasm/pkg`, `null` when there is none. */
    size: { wasm: number; base64: number; glue: number; gzip: number; total: number; budget: number } | null;
  }
}

const root = fileURLToPath(new URL("../../../../", import.meta.url));

function vectorFiles(): Record<string, string> {
  const files: Record<string, string> = {};
  for (const top of ["generated", "accounts", "crypto"]) {
    const dir = join(root, "vectors", top);
    for (const rel of readdirSync(dir, { recursive: true, encoding: "utf8" })) {
      if (rel.endsWith(".json")) {
        files[`${top}/${rel.split("\\").join("/")}`] = readFileSync(join(dir, rel), "utf8");
      }
    }
  }
  return files;
}

function expectedFailures(): string[] {
  const text = readFileSync(join(root, "crates/dybw-vectors/expected-failures.txt"), "utf8");
  const lines = text.split("\n").map((l) => l.trim());
  return lines.filter((l) => l !== "" && !l.startsWith("#")).map((l) => l.split(" ")[0]);
}

export default function setup(project: TestProject): void {
  project.provide("files", vectorFiles());
  project.provide("expectedFailures", expectedFailures());
  const wasm = join(root, "crates/dybw-core-wasm/js/pkg/dybw_core_wasm_bg.wasm");
  project.provide("wasm", readFileSync(wasm).toString("base64"));
  const plain = join(root, "target-wasm/pkg");
  project.provide("size", existsSync(join(plain, "dybw_core_wasm_bg.wasm")) ? sizeReport(plain) : null);
}
