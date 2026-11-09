// A panic traps the instance (`panic = "abort"`): the hook reports where through `log`, never the message. The
// trapped instance stays callable with its memory, so the host first calls `lock()` on every live session (which
// drops and wipes the keys), then loads a fresh glue module: the glue caches its instance, so calling its init again
// does not re-instantiate.
import { expect, inject, test } from "vitest";
import { hostPorts } from "./ports";
import { account, profile, serverPorts } from "./server";

type Glue = typeof import("../pkg/dybw_core_wasm.js");

const wasm = () => Uint8Array.from(atob(inject("wasm")), (c) => c.charCodeAt(0));

/** A fresh glue module, so a fresh instance: the query string makes it another module. */
async function instantiate(glue: Promise<unknown>): Promise<Glue> {
  const g = (await glue) as Glue;
  await g.default({ module_or_path: wasm() });
  return g;
}

test("a panic traps, reports no value, lock still wipes a live session, and a new instance answers locked", async () => {
  const logged: string[] = [];
  const ports = { ...hostPorts(), log: (m: string) => void logged.push(m) };
  const first = await instantiate(import("../pkg/dybw_core_wasm.js?instance=first"));
  first.init(ports);
  const cose = account(new Map(Object.entries(inject("files"))), "cose-v2");
  const live = new first.WasmSession(serverPorts(cose).ports, "obsidian");
  await live.unlock(profile(cose), "vectors", cose.password);

  expect(() => first.panicForTest("secret-sentinel")).toThrow(WebAssembly.RuntimeError);
  expect(logged.join("\n")).toContain("panicked");
  expect(logged.join("\n")).not.toContain("secret-sentinel");
  // The trapped instance still holds the unlocked keys, which is why the host locks it before dropping it.
  await expect(live.planPass("{}", [], [])).resolves.toContain("actions");
  expect(() => live.lock()).not.toThrow();
  await expect(live.planPass("{}", [], [])).rejects.toBe("locked");

  const second = await instantiate(import("../pkg/dybw_core_wasm.js?instance=second"));
  expect(second).not.toBe(first);
  second.init(ports);
  const session = new second.WasmSession(hostPorts(), "obsidian");
  await expect(session.planPass("{}", [], [])).rejects.toBe("locked");
});
