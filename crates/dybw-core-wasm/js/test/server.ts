// A fake Bitwarden server as the harness's `http` port, for a vector account, with ciphers and organizations if
// given: the JS mirror of `dybw_vectors::server::VectorServer` and `account_keys`' profile and prelogin, enough for the session
// to log in, unlock and sync.
import { hostPorts } from "./ports";

/** The vector server's base URL (`dybw_vectors::server::SERVER`). */
export const SERVER = "https://vectors.invalid";

type Account = {
  email: string;
  password: string;
  kdf: { type: "pbkdf2"; iterations: number };
  profileKey: string;
  profile?: { accountKeys?: unknown };
  /** The 64-byte user key and the PKCS#8 private key, base64; the organizations' keys wrapped to it. */
  userKey: string;
  privateKey?: string;
  organizations?: { id: string; name: string; wrapped: string }[];
};

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

/** The account's private key encrypted with its user key (type 2: AES-256-CBC, then HMAC-SHA256 over iv and data). */
export async function wrappedPrivateKey(a: Account): Promise<string> {
  const key = unb64(a.userKey);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const aes = await crypto.subtle.importKey("raw", key.slice(0, 32), "AES-CBC", false, ["encrypt"]);
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, unb64(a.privateKey ?? "")));
  const hmac = await crypto.subtle.importKey("raw", key.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmac, new Uint8Array([...iv, ...data])));
  return `2.${b64(iv)}|${b64(data)}|${b64(mac)}`;
}

export function account(files: Map<string, string>, name: string): Account {
  return JSON.parse(files.get(`accounts/${name}.json`) ?? "null") as Account;
}

/** The session's profile JSON for `account`. */
export function profile(a: Account): string {
  const device = { deviceName: "test", deviceType: 8, clientName: "cli", clientVersion: "0" };
  return JSON.stringify({ server: SERVER, email: a.email, apiOrigin: SERVER, clientId: "vectors", ...device });
}

/** The harness's ports with `http` answering as the vector server for `a`; `requests` records each path. */
export function serverPorts(a: Account, extra: { privateKey?: string; ciphers?: unknown[] } = {}) {
  const organizations = (a.organizations ?? []).map((o) => ({ id: o.id, name: o.name, key: o.wrapped, enabled: true }));
  const privateKey = extra.privateKey ?? null;
  const profile = { id: "vectors-user", email: a.email, key: a.profileKey, privateKey, organizations };
  const sync = { profile: { ...profile, accountKeys: a.profile?.accountKeys }, folders: [], ciphers: extra.ciphers ?? [] };
  const routes: Record<string, unknown> = {
    "POST /identity/connect/token": { access_token: "vectors-token", expires_in: 3600 },
    "POST /identity/accounts/prelogin": { kdf: 0, kdfIterations: a.kdf.iterations },
    "GET /api/sync": sync,
  };
  const requests: string[] = [];
  const ports = {
    ...hostPorts(),
    async http(method: string, url: string, headers: string): Promise<[number, Uint8Array]> {
      const route = `${method} ${new URL(url).pathname}`;
      requests.push(route);
      // The rejection fails the session's call, so the test; it names the header, never its value.
      const pairs: unknown = JSON.parse(headers);
      const isPair = (h: unknown) => Array.isArray(h) && h.length === 2 && h.every((s) => typeof s === "string");
      if (!Array.isArray(pairs) || !pairs.every(isPair)) throw `${route}: headers are not [[name, value], ...]`;
      const named = (n: string) => (pairs as [string, string][]).some(([k]) => k.toLowerCase() === n);
      if (route === "GET /api/sync" && !named("authorization")) throw `${route}: no Authorization header`;
      const body = routes[route] ?? { message: `not faked: ${route}` };
      return [route in routes ? 200 : 404, new TextEncoder().encode(JSON.stringify(body))];
    },
  };
  return { ports, requests };
}
