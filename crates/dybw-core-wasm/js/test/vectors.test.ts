// The conformance vectors and the crypto known answers, run by the WASM build with the harness's JS ports.
import { beforeAll, describe, expect, inject, test } from "vitest";
import init, { runKnownAnswers, runVectors } from "../pkg/dybw_core_wasm.js";
import { hostPorts, RSA_KEY_ERROR } from "./ports";

type Report = { results: [string, string | null][]; failures: string[] };

const files = new Map(Object.entries(inject("files")));

/** What the native runner runs: one entry per scenario and kind of expectation it carries. */
function scenarioCount(): number {
  let count = 0;
  for (const [path, text] of files) {
    if (/^generated\/(bwss|obsidian)\/.*\.json$/.test(path)) {
      const expect = (JSON.parse(text) as { expect: Record<string, unknown> }).expect;
      count += ["read", "write", "plan"].filter((k) => expect[k] != null).length;
    }
  }
  return count;
}

beforeAll(async () => {
  const wasm = Uint8Array.from(atob(inject("wasm")), (c) => c.charCodeAt(0));
  await init({ module_or_path: wasm });
});

describe("the WASM build", () => {
  test("runs every vector, failing only the listed ones", async () => {
    const ports = hostPorts();
    const decrypt = ports.rsaOaepDecrypt;
    let rsaCalls = 0;
    ports.rsaOaepDecrypt = (...args) => (rsaCalls++, decrypt(...args));
    const report = JSON.parse(await runVectors(files, ports)) as Report;
    expect(report.failures).toEqual([]);
    expect(rsaCalls, "the organization vectors go through WebCrypto").toBeGreaterThan(0);
    expect(report.results.length).toBe(scenarioCount());
    const failing = [...new Set(report.results.filter(([, e]) => e !== null).map(([id]) => id))].sort();
    expect(failing).toEqual([...inject("expectedFailures")].sort());
    console.log(`vectors: ${report.results.length} run, ${failing.length} expected failures, ${rsaCalls} RSA calls`);
  });

  test("passes the crypto known answers", async () => {
    const report = JSON.parse(await runKnownAnswers(files, hostPorts())) as Report;
    expect(report.failures).toEqual([]);
    expect(report.results).toEqual(["pbkdf2", "argon2id", "cose", "sdk", "msgpack", "marks"].map((n) => [n, null]));
    console.log(`known answers: ${report.results.length} passed`);
  });
});

describe("the harness's ports", () => {
  test("rsaOaepDecrypt rejects a key it cannot import with exactly RSA_KEY_ERROR", async () => {
    const ports = hostPorts();
    await expect(ports.rsaOaepDecrypt(new Uint8Array([1, 2, 3]), "SHA-1", new Uint8Array(256))).rejects.toBe(
      RSA_KEY_ERROR,
    );
  });
});
