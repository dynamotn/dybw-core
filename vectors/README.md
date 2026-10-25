# Conformance vectors

Scenarios that bwss and the Obsidian plugin must both satisfy, following data
model **1.5**. Each scenario is written once as a plaintext **source** under
`vectors/src/`, and the generator turns it into one **generated** file per
namespace under `vectors/generated/<ns>/`. Adapters in each tool read only the
generated files. Both formats are pinned by JSON Schemas (`additionalProperties`
is `false` at every level, except where noted):

- `schema/source.schema.json` for sources;
- `schema/scenario.schema.json` for generated files. It `$ref`s the shared
  definitions (`expect`, `device`, `local`, `options`, `canonicalRequest`) in
  `source.schema.json` by relative URI, so a validator must be given both files
  (for Python, a `referencing.Registry` keyed by `$id`).

Generated files are deterministic: building twice gives identical bytes. No
real account or secret is involved; every key comes from the fixed seeds in
`vectors/accounts/`.

## Source format

One JSON object per file.

| Key | Type | Meaning |
|---|---|---|
| `id` | string | `^[a-z0-9-]+(/[a-z0-9-]+)*$`; the path below `vectors/src/` without `.json` |
| `spec` | `"1.5"` | The data model version |
| `sections` | `["§5", ...]` | The sections of the data model the scenario tests (at least one) |
| `account` | string | Name of a fixed account in `vectors/accounts/` |
| `namespaces` | subset of `["bwss", "obsidian"]` | The scenario applies to each one listed. In field names and values, `{ns}` stands for the namespace |
| `options` | object | `organizations` (bool, default `false`), `policy` (`"ask"` default, `"prefer-remote"`, `"prefer-local"`) |
| `ciphers` | array | Plaintext ciphers, below |
| `device` | object, optional | The device's sync state, below |
| `local` | object, optional | `{ id: string \| null }`: the device's local values; `null` means missing. A sync scenario lists every id it plans for, so a missing value is always written `null`, never left out (the plugin treats both alike) |
| `operation` | object, optional | The write the tool performs, below |
| `expect` | object | At least one of `read`, `write`, `plan`, below |

### Plaintext cipher

Only `id`, `type` and `name` are required. An absent key means its default.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | | Cipher id |
| `type` | 1, 2 or 3 | | 1 login, 2 secure note, 3 card (a card is skipped as `wrong-type`) |
| `name` | string | | |
| `notes` | string or `null` | `null` | `null`, `""` and a text are three different states |
| `login` | object or `null` | `null` | `{ username, password, uris: [string], totp, passwordHistory: [{ password, lastUsedDate }] }`; `username`, `password`, `totp` may be `null` |
| `fields` | array or `null` | `null` | `[{ name, value, type: 0 \| 1 }]`, in order; `null` and `[]` differ |
| `folderId` | string or `null` | `null` | |
| `organizationId` | string or `null` | `null` | |
| `itemKey` | bool | `false` | `true` gives the cipher a per-item key |
| `creationDate`, `revisionDate`, `deletedDate` | ISO 8601 or `null` | `null` | |
| `edit`, `viewPassword` | bool | `true` | Organization permissions |
| `pascalCase` | bool | `false` | `true` emits the server keys in PascalCase |
| `tamper` | array of paths | `[]` | Source only, never emitted: each listed string is encrypted, then the first byte of its MAC is flipped, so it fails the MAC check. Paths are `name`, `notes`, `key` (the wrapped item key), `login.username`, `login.password`, `login.totp`, `login.uris[i].uri`, `login.passwordHistory[i].password`, `fields[i].name`, `fields[i].value`; each must be a string the cipher actually encrypts |
| `extra` | object | `{}` | Unknown properties, passed through verbatim. Every key must match `^x[A-Za-z0-9]+$` (the `x` convention), so it can never collide with a known key |

### `device`

```json
{ "base": { "<id>": { "cipher": "...", "revisionDate": "...", "value": "plaintext", "pushConfirmed": true } },
  "pendingCreates": ["<id>"] }
```

`value` is plaintext. The adapter computes the tool's own fingerprint from it,
so vectors never carry a tool-specific fingerprint. `pushConfirmed` is optional.

### `operation`

One of:

- `{ "kind": "set-value", "id", "value" }`;
- `{ "kind": "create", "id", "value", "folderId": string | null }`;
- `{ "kind": "delete", "id" }`.

An optional `fresh` holds the cipher the server returns when the tool
refetches after an out-of-date rejection (data model §6.5): a plaintext cipher
in a source, a server-shaped cipher in a generated file. When present, the
first write is rejected as out of date and the tool must re-apply its own
change to `fresh`.

- **Values.** `value` follows the read value rule: `base64:<b64>`
  (canonical, standard alphabet with `=` padding) stands for bytes that are not
  valid UTF-8, and any other string is that UTF-8 text. The generator rejects a
  `base64:` value that is not canonical or that decodes to valid UTF-8. As in
  reads, no operation value is plain text that starts with `base64:`.
- **Requests after a refetch.** With `fresh`, `expect.write.requests` lists
  only the requests sent after the refetch; the rejected first write is not
  listed. An empty list means the tool gave up (data model §6.5). Each listed
  request's `lastKnownRevisionDate` is then the `revisionDate` of `fresh`.
- **Confirmations.** A write vector shows the requests after every
  confirmation the data model asks for was answered "go ahead" (the first
  write-back to a hand-marked login, §6.1; the first write to an organization
  item, §9). The questions themselves are not part of a write vector.

### `expect`

- `read`: `{ items, skipped, uninspectable, duplicates? }`.
  - `items`: `[{ cipher, id, value, source }]`, sorted by `id`, with `source`
    one of `field`, `notes`, `login-password`, `note-body`. `value` is the
    decoded secret, under these rules:
    - a value read under `{ns}:encoding=base64` is base64-decoded to bytes;
      when those bytes are valid UTF-8 they are written as that text;
    - otherwise they are *binary* (not valid UTF-8, data model §3.2) and are
      written as `"base64:<b64>"`, where `<b64>` is canonical: re-encoded
      from the decoded bytes with the standard alphabet and `=` padding,
      never copied from the stored string;
    - a value read without an encoding mark is written as stored, never
      prefixed; no vector uses a plain value that starts with `base64:`.

    An optional `attributes` (object, name to value) lists
    the item's stored lookup attributes (`{ns}:attr:<name>`, data model §3.4)
    with names after the prefix and values exactly as stored; derived
    attributes are not listed. When it is absent, attributes are not checked.
  - `skipped`: `[{ cipher, reason }]`, with `reason` from the table below.
  - `uninspectable`: `[cipher id]`.
  - `duplicates`: `[{ id, kept, left: [cipher id] }]`.
- `write`: either `{ "requests": [CanonicalRequest] }` or
  `{ "error": "too-long" | "notes-hold-user-text" | "value-source-changed" }`.
- `plan`: `[{ kind, id }]` sorted by `id`, with `kind` one of `pull`, `push`,
  `adopt`, `clear-local`, `forget`, `create`; or
  `{ kind: "conflict", id, conflict }` with `conflict` one of `both-changed`,
  `local-unsynced`, `deleted-remotely`, `organization-claim`,
  `organization-push`.

  The plan covers every id found in the read items, in `device.base` or in
  `device.pendingCreates`; an id that needs nothing has no entry. The
  `confirmed` marker the plugin puts on a push the user just agreed to is not
  part of the plan: no vector answers a conflict.

## Generated format

The source object with these differences:

- `namespaces` is replaced by `namespace`, a string (`bwss` or `obsidian`);
  the file lives at `vectors/generated/<namespace>/<id>.json`;
- `generator` (string) records the generator version;
- `{ns}` is expanded in every string (and object key) except the top-level
  `id` and `sections`; there is no escape for a literal `{ns}`;
- every `ciphers[i]` (and `operation.fresh`) is a server-shaped cipher:
  - every string the server stores encrypted (`name`, `notes`, login
    `username`, `password`, `totp`, URIs, field names and values, history
    passwords) is an EncString of type 2, `2.<iv>|<data>|<mac>`;
  - `key` is the per-item key when the source set `itemKey`: 64 bytes wrapped
    as an EncString of type 2 under the owner key (the user key, or the
    organization key when `organizationId` is set), and all the cipher's
    strings are then encrypted under the item key. A `fresh` cipher with the
    id of a cipher in `ciphers` reuses that cipher's item key;
  - the source's `login.passwordHistory` moves to the cipher's top-level
    `passwordHistory` (`PasswordHistory`); `login.uris[].match` is always
    `null`; a type 2 cipher has `secureNote: { type: 0 }`;
  - cipher ids are unique within `ciphers`;
  - keys are camelCase, or PascalCase (`Id`, `Name`, `Login`, `Uris`, ...)
    when the source set `pascalCase`; both spellings are accepted by the
    schema, and a cipher uses one of them;
  - `login.uris` is `[{ uri, match }]`, a secure note carries
    `secureNote: { type }`, dates and `folderId`/`organizationId` stay plain;
  - the source's `extra` properties are spread at the top level of the
    cipher, verbatim, with the same spelling in camelCase and PascalCase
    ciphers. Beyond the known keys, only `^x[A-Za-z0-9]+$` keys are allowed;
    a cipher is either entirely camelCase or entirely PascalCase, nested
    objects included (the schema is a `oneOf` of the two).
- `device`, `local` and `expect` stay plaintext.

## Canonical write body

`CanonicalRequest` is the decrypted body as the tool would send it:

| Key | Meaning |
|---|---|
| `method` | `"POST"`, `"PUT"`, or `"trash"` for the delete step |
| `cipher` | cipher id, or `null` when creating |
| `type`, `name`, `notes` | as in the cipher |
| `login` | `{ username, password, uris, totp, passwordHistory: [password] }`, or `null` |
| `fields` | `[{ name, value, type }]`, in order |
| `organizationId`, `folderId` | string or `null` |
| `lastKnownRevisionDate` | string or `null` |
| `hasItemKey` | bool |
| `extra` | the unknown properties passed through (`x` keys, as in a cipher) |

A `trash` request carries only `method` and `cipher` (a string). `POST` carries every key with `cipher: null`; `PUT` carries every key with `cipher` set. A field `value` may be `null`. Dates written by the tool become the literal `"<now>"`. The
comparison is a deep equality after both sides are canonicalized: the adapters
canonicalize the tool's real request by decrypting it with the scenario's keys.

Conventions the expectations follow:

- **Cleared notes are `null`.** When a write clears the notes (a stale copy
  after a value fits its field again, data model §6.4; a delete, §8.2), the
  request carries `notes: null`, never `""`.
- **Tool-defined parts of a create.** The data model leaves a new item's name
  and the tool's other fields open (§6.2). For a `POST`, the comparison ignores
  `name` and every `{ns}:*` field other than `{ns}:id` and `{ns}:password`:
  adapters drop them from both sides before comparing. The vectors write the
  name as the literal `"<tool-defined>"`.
- **Delete.** The server is taken to return the `PUT` body as sent; the trash
  decision (§8.2 step 3) is made on it.
- **Added fields go last.** A field a tool adds (`{ns}:location`,
  `{ns}:encoding`, `{ns}:password`) is appended after the existing fields.
- **Not compared.** The canonical body does not check
  `login.passwordRevisionDate` (§6.1) or `encryptedFor` (§6.3).
- **Password history.** A write-back to the login password puts the old
  password first, and the vectors never start from a full history of 5. The
  eviction of an entry from a full history arrives with ADR 0016 (password
  history protection) in M3.

## Reason codes

Used in `expect.read.skipped[].reason`.

| Code | Meaning |
|---|---|
| `wrong-type` | The cipher is neither a login nor a secure note |
| `encoding-on-user-source` | An encoding mark sits on a value the user typed (such as the login password) |
| `unknown-location` | The `{ns}:location` mark names a location that does not exist |
| `unknown-encoding` | The `{ns}:encoding` mark names an encoding that does not exist, or that the namespace does not implement. A namespace that implements no encoding (`obsidian`) reports it for every non-blank mark, before any other encoding check (such as `encoding-on-user-source`) |
| `invalid-id` | The `{ns}:id` mark is not a valid identifier |
| `reserved-id` | The `{ns}:id` mark uses a reserved identifier |
| `view-password-hidden` | An organization hides the password from this user |
| `organizations-off` | Reserved, not used in read skips: an organization cipher the tool does not read is listed in `uninspectable` (data model §4, §9) |
| `undecryptable` | Reserved, not used in read skips: a cipher whose item key or field names fail to decrypt is listed in `uninspectable` (data model §4) |
| `newer-format` | The mark was written by a newer data model than this tool supports |
