// A fake Bitwarden server as the harness's `http` port, for a vector account without ciphers or organizations: the
// JS mirror of `dybw_vectors::server::VectorServer` and `account_keys`' profile and prelogin, enough for the session
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
};

export function account(files: Map<string, string>, name: string): Account {
  return JSON.parse(files.get(`accounts/${name}.json`) ?? "null") as Account;
}

/** The session's profile JSON for `account`. */
export function profile(a: Account): string {
  const device = { deviceName: "test", deviceType: 8, clientName: "cli", clientVersion: "0" };
  return JSON.stringify({ server: SERVER, email: a.email, apiOrigin: SERVER, clientId: "vectors", ...device });
}

/** The harness's ports with `http` answering as the vector server for `a`; `requests` records each path. */
export function serverPorts(a: Account) {
  const profile = { id: "vectors-user", email: a.email, key: a.profileKey, privateKey: null, organizations: [] };
  const sync = { profile: { ...profile, accountKeys: a.profile?.accountKeys }, folders: [], ciphers: [] };
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
