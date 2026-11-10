// The session half of the boundary in WASM: a real `WasmSession` over the harness's ports, logged in to the vector
// server (`server.ts`) as the `cose-v2` account, the WASM mirror of the native `a_session_unlocks_and_locks`.
import { beforeAll, expect, inject, test } from "vitest";
import init, { WasmSession } from "../pkg/dybw_core_wasm.js";
import { account, profile, serverPorts, wrappedPrivateKey } from "./server";

const files = new Map(Object.entries(inject("files")));
const cose = account(files, "cose-v2");
/** Every rejection is the JSON text `{"code", "message", …fields}`. */
const LOCKED = JSON.stringify({ code: "locked", message: "Bitwarden is locked" });

beforeAll(async () => {
  const wasm = Uint8Array.from(atob(inject("wasm")), (c) => c.charCodeAt(0));
  await init({ module_or_path: wasm });
});

/** `p`, or a rejection when it has not settled within `ms`: a call stranded by a throw never settles. */
function settled<T>(p: Promise<T>, ms = 20_000): Promise<T> {
  const late = new Promise<never>((_, reject) => setTimeout(() => reject(new Error("never settled")), ms));
  return Promise.race([p, late]);
}

/** Resolves once `ready()` is true. */
async function until(ready: () => boolean): Promise<void> {
  while (!ready()) await new Promise((resolve) => setTimeout(resolve, 5));
}

/** The vector server's ports, with a fast clock for the hub's backoff and a count of socket opens. */
function ports() {
  const { ports, requests } = serverPorts(cose);
  const drawn: Uint8Array[] = [];
  const random = ports.random;
  const counts = { socketOpen: 0 };
  const socketOpen = ports.socketOpen;
  return {
    requests,
    drawn,
    counts,
    ports: {
      ...ports,
      sleepMs: (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, Math.min(ms, 10))),
      random(len: number) {
        const bytes = random(len);
        drawn.push(bytes);
        return bytes;
      },
      socketOpen(): Promise<number> {
        counts.socketOpen++;
        return socketOpen();
      },
    },
  };
}

test("a session unlocks, plans and syncs a local value, and locks", async () => {
  const { ports: p, requests, drawn } = ports();
  const s = new WasmSession(p, "obsidian");
  const summary = JSON.parse(await s.unlock(profile(cose), "vectors", cose.password));
  expect(summary.securityVersion).toBe(2);
  expect(summary.orgProblems).toEqual([]);
  expect(requests).toEqual(["POST /identity/connect/token", "GET /api/sync", "POST /identity/accounts/prelogin"]);

  const plan = JSON.parse(await s.planPass("{}", ["alpha"], ["local-value"]));
  expect(plan).toEqual({ actions: [], massClear: null });
  const report = JSON.parse(await s.runSync("{}", ["alpha"], ["local-value"]));
  expect(report.errors).toEqual([]);
  expect(report.passes).toBeGreaterThanOrEqual(1);

  s.lock();
  await expect(s.planPass("{}", [], [])).rejects.toBe(LOCKED);
  await expect(s.runSync("{}", [], [])).rejects.toBe(LOCKED);
  await expect(s.runHub(() => {}, () => false)).rejects.toBe(LOCKED);
  const wrong = JSON.stringify({ code: "wrong-password", message: "wrong master password" });
  await expect(s.unlock(profile(cose), "vectors", "wrong")).rejects.toBe(wrong);
  const elsewhere = JSON.stringify({ ...JSON.parse(profile(cose)), apiOrigin: "https://identity.bitwarden.com" });
  const refused = await s.unlock(elsewhere, "vectors", cose.password).catch((e: unknown) => JSON.parse(String(e)));
  expect(refused.code, "an API key entered for another server is not sent").toBe("wrong-origin");
  await expect(s.planPass("{}", [], [])).rejects.toBe(LOCKED);

  expect(drawn.length, "the session drew random bytes").toBeGreaterThan(0);
  expect(drawn.every((d) => d.every((b) => b === 0)), "every random array is wiped once copied").toBe(true);
});

test("a host that follows redirects sends nothing to a self-hosted origin until it is acknowledged (ADR 0018)", async () => {
  const { ports: base, requests } = ports();
  const s = new WasmSession({ ...base, refusesRedirects: () => false }, "obsidian");
  const refused = await s.unlock(profile(cose), "vectors", cose.password).catch((e: unknown) => JSON.parse(String(e)));
  expect(refused).toMatchObject({ code: "origin-not-acknowledged", origin: "https://vectors.invalid" });
  expect(requests, "no request left, not even /connect/token").toEqual([]);

  await s.acknowledgeOrigin("https://vectors.invalid");
  expect(JSON.parse(await s.acknowledgedOrigins())).toEqual(["https://vectors.invalid"]);
  await s.unlock(profile(cose), "vectors", cose.password);
  expect(requests[0]).toBe("POST /identity/connect/token");

  await s.forgetOrigin("https://vectors.invalid");
  expect(JSON.parse(await s.acknowledgedOrigins())).toEqual([]);
  s.lock();
});

test("the hub runs until lock, and its promise settles", async () => {
  const { ports: p, counts } = ports();
  const s = new WasmSession(p, "obsidian");
  await s.unlock(profile(cose), "vectors", cose.password);
  const hub = s.runHub(() => {}, () => false);
  await until(() => counts.socketOpen >= 2);
  s.lock();
  await expect(settled(hub)).resolves.toBeUndefined();
});

test("a refused socket renews the hub's token once per run of refusals, then backs off", async () => {
  const { ports: p, counts, requests } = ports();
  const s = new WasmSession(p, "obsidian");
  await s.unlock(profile(cose), "vectors", cose.password);
  const logins = () => requests.filter((r) => r === "POST /identity/connect/token").length;
  expect(logins()).toBe(1);
  // The harness refuses every socket, as a server refuses an expired token.
  const hub = s.runHub(() => {}, () => false);
  await until(() => counts.socketOpen >= 4);
  s.lock();
  await expect(settled(hub)).resolves.toBeUndefined();
  expect(logins(), "renewed at once after the first refusal, not after each").toBe(2);
});

test("a stop() that throws stops the hub", async () => {
  const { ports: p } = ports();
  const s = new WasmSession(p, "obsidian");
  await s.unlock(profile(cose), "vectors", cose.password);
  const hub = s.runHub(() => {}, () => {
    throw new Error("stop failed");
  });
  await expect(settled(hub, 5_000)).resolves.toBeUndefined();
  s.lock();
});

test("a port that throws synchronously fails the call, leaves the session usable, and names no URL", async () => {
  const { ports: base } = ports();
  let throwing = "";
  const thrown: Record<string, number> = {};
  const thrower =
    <A extends unknown[], R>(name: string, f: (...a: A) => R) =>
    (...a: A): R => {
      thrown[name] = (thrown[name] ?? 0) + Number(throwing === name);
      if (throwing === name) throw new Error(`${name} failed for https://vectors.invalid/?access_token=sentinel`);
      return f(...a);
    };
  const p = {
    ...base,
    http: thrower("http", base.http),
    storageSave: thrower("storageSave", base.storageSave),
    socketOpen: thrower("socketOpen", base.socketOpen),
  };
  const s = new WasmSession(p, "obsidian");
  const noUrl = (e: unknown) => typeof e === "string" && !e.includes("vectors.invalid") && !e.includes("sentinel");

  throwing = "http";
  const failed = await settled(s.unlock(profile(cose), "vectors", cose.password)).catch((e: unknown) => e);
  expect(noUrl(failed), `unlock rejected with ${String(failed)}`).toBe(true);
  await expect(s.planPass("{}", [], [])).rejects.toBe(LOCKED);

  throwing = "";
  await settled(s.unlock(profile(cose), "vectors", cose.password));
  throwing = "storageSave";
  const sync = await settled(s.runSync("{}", [], [])).catch((e: unknown) => e);
  expect(noUrl(sync), `runSync rejected with ${String(sync)}`).toBe(true);
  expect(thrown.storageSave ?? 0, "storageSave threw").toBeGreaterThanOrEqual(1);
  expect(JSON.parse(String(sync))).toMatchObject({ code: "port", message: expect.stringMatching(/^host storageSave threw/) });
  throwing = "";
  await expect(settled(s.planPass("{}", [], []))).resolves.toContain("actions");

  throwing = "socketOpen";
  const hub = s.runHub(() => {}, () => false);
  await until(() => (thrown.socketOpen ?? 0) >= 2);
  s.lock();
  await expect(settled(hub)).resolves.toBeUndefined();
  await expect(s.planPass("{}", [], [])).rejects.toBe(LOCKED);
});

test("a conflict reaches JS with its label and organization", async () => {
  const org = account(files, "org");
  const scenario = JSON.parse(files.get("generated/obsidian/sync/org-claim-with-local-asks.json") ?? "null");
  const { ports: p } = serverPorts(org, { privateKey: await wrappedPrivateKey(org), ciphers: scenario.ciphers });
  const s = new WasmSession(p, "obsidian");
  const all = JSON.stringify({ ...JSON.parse(profile(org)), organizations: "all" });
  const summary = JSON.parse(await s.unlock(all, "vectors", org.password));
  expect(summary.orgProblems).toEqual([]);
  const report = JSON.parse(await s.runSync("{}", ["alpha"], ["shared-secret"]));
  expect(report.conflicts).toEqual([
    { id: "alpha", kind: "organization-claim", label: "Login c1", organization: "org-a", organizationName: "Org A" },
  ]);
  s.lock();
});

test("a remembered user key unlocks again without the password, and only while it opens the private key", async () => {
  const org = account(files, "org");
  const { ports: p, requests } = serverPorts(org, { privateKey: await wrappedPrivateKey(org) });
  const s = new WasmSession(p, "obsidian");
  await expect(Promise.resolve().then(() => s.exportUserKey())).rejects.toBe(LOCKED);
  const summary = JSON.parse(await s.unlock(profile(org), "vectors", org.password));
  const key = s.exportUserKey();
  expect(key).toBe(org.userKey);
  s.lock();
  await expect(Promise.resolve().then(() => s.exportUserKey())).rejects.toBe(LOCKED);

  requests.length = 0;
  const again = JSON.parse(await s.unlockWithKey(profile(org), "vectors", key));
  expect(again.userKeyId).toBe(summary.userKeyId);
  expect(requests, "login and sync, no prelogin").toEqual(["POST /identity/connect/token", "GET /api/sync"]);
  expect(JSON.parse(await s.planPass("{}", [], []))).toEqual({ actions: [], massClear: null });

  const wrong = JSON.stringify({ code: "wrong-password", message: "wrong master password" });
  await expect(s.unlockWithKey(profile(org), "vectors", cose.userKey)).rejects.toBe(wrong);
  await expect(s.planPass("{}", [], [])).rejects.toBe(LOCKED);
  const bad = await s.unlockWithKey(profile(org), "vectors", "not base64!").catch((e: unknown) => JSON.parse(String(e)));
  expect(bad.code).toBe("invalid");
});
