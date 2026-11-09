// The size budget (D12): the module without `vectors`, as base64, plus its glue after esbuild minify must fit in
// 1 179 648 bytes, the share of the plugin's 1 MiB-class `main.js` left to the core. Build it first:
// `scripts/build-wasm.sh` (to `target-wasm/pkg`).
import { expect, inject, test } from "vitest";

test("the module without vectors fits the size budget", () => {
  const size = inject("size");
  expect(size, "no build at target-wasm/pkg: run scripts/build-wasm.sh").not.toBeNull();
  expect(size?.budget).toBe(1_179_648);
  console.log(`size: ${JSON.stringify(size)}`);
  expect(size?.total).toBeLessThanOrEqual(1_179_648);
});
