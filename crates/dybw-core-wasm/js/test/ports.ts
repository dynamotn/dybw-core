// The harness's `HostPorts`, on the platform alone: WebCrypto, hash-wasm, timers and memory. It follows the Host
// contract (crates/dybw-core-wasm/src/host.rs): a borrowed view into WASM memory is copied before the first await,
// and that copy is wiped once used; a rejection is a plain text that never includes a URL, a body or a secret.
import { argon2id } from "hash-wasm";

/** What `rsaOaepDecrypt` rejects with when the PKCS#8 key cannot be imported (`RSA_KEY_ERROR`). */
export const RSA_KEY_ERROR = "key";
/** Every request is bounded: the keys a running call holds outlive a `lock` until the request settles. */
export const HTTP_TIMEOUT_MS = 30_000;

const wipe = (...copies: (Uint8Array | undefined)[]) => copies.forEach((c) => c?.fill(0));

export function hostPorts() {
  const storage = new Map<string, Uint8Array>();
  const secrets = new Map<string, string>();
  return {
    nowMs: () => Date.now(),
    sleepMs: (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
    refusesRedirects: () => true,
    random: (len: number) => crypto.getRandomValues(new Uint8Array(len)),
    async http(method: string, url: string, headers: string, body?: Uint8Array): Promise<[number, Uint8Array]> {
      const copy = body?.slice();
      try {
        const res = await fetch(url, {
          method,
          headers: JSON.parse(headers) as [string, string][],
          body: copy,
          redirect: "error",
          signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
        });
        return [res.status, new Uint8Array(await res.arrayBuffer())];
      } catch {
        throw "the request failed";
      } finally {
        wipe(copy);
      }
    },
    storageLoad: async (key: string) => storage.get(key)?.slice() ?? null,
    storageSave: async (key: string, value: Uint8Array) => void storage.set(key, value.slice()),
    storageRemove: async (key: string) => void storage.delete(key),
    secretLoad: async (key: string) => secrets.get(key) ?? null,
    secretSave: async (key: string, value: string) => void secrets.set(key, value),
    secretRemove: async (key: string) => void secrets.delete(key),
    async argon2id(password: Uint8Array, salt: Uint8Array, iterations: number, memoryKib: number, parallelism: number) {
      const [pw, s] = [password.slice(), salt.slice()];
      try {
        const options = { password: pw, salt: s, iterations, memorySize: memoryKib, parallelism, hashLength: 32 };
        return await argon2id({ ...options, outputType: "binary" });
      } catch {
        throw "argon2id failed";
      } finally {
        wipe(pw, s);
      }
    },
    async rsaOaepDecrypt(pkcs8: Uint8Array, hash: string, ciphertext: Uint8Array) {
      const [der, ct] = [pkcs8.slice(), ciphertext.slice()];
      try {
        let key: CryptoKey;
        try {
          key = await crypto.subtle.importKey("pkcs8", der, { name: "RSA-OAEP", hash }, false, ["decrypt"]);
        } catch {
          throw RSA_KEY_ERROR;
        }
        try {
          return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, ct));
        } catch {
          throw "decryption failed";
        }
      } finally {
        wipe(der, ct);
      }
    },
    socketOpen: async (): Promise<number> => {
      throw "the harness has no sockets";
    },
    socketSend: async () => {
      throw "the harness has no sockets";
    },
    socketRecv: async () => null,
    socketClose: () => {},
    log: (message: string) => console.log(message),
  };
}
