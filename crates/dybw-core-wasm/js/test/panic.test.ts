// A panic traps the instance (`panic = "abort"`): the hook reports where through `log`, never the message, and the
// host recovers by instantiating the module again, which starts locked.
import { expect, inject, test } from "vitest";
import { hostPorts } from "./ports";

type Glue = typeof import("../pkg/dybw_core_wasm.js");

const wasm = () => Uint8Array.from(atob(inject("wasm")), (c) => c.charCodeAt(0));

/** A fresh glue module, so a fresh instance: the query string makes it another module. */
async function instantiate(glue: Promise<unknown>): Promise<Glue> {
  const g = (await glue) as Glue;
  await g.default({ module_or_path: wasm() });
  return g;
}

test("a panic traps, reports no value, and a new instance answers locked", async () => {
  const logged: string[] = [];
  const ports = { ...hostPorts(), log: (m: string) => void logged.push(m) };
  const first = await instantiate(import("../pkg/dybw_core_wasm.js?instance=first"));
  first.init(ports);
  expect(() => first.panicForTest("secret-sentinel")).toThrow(WebAssembly.RuntimeError);
  expect(logged.length).toBeGreaterThan(0);
  expect(logged.join("\n")).not.toContain("secret-sentinel");

  const second = await instantiate(import("../pkg/dybw_core_wasm.js?instance=second"));
  second.init(ports);
  const session = new second.WasmSession(hostPorts(), "obsidian");
  await expect(session.planPass("{}", [], [])).rejects.toBe("locked");
});
