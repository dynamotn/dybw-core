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
| `local` | object, optional | `{ id: string \| null }`: the device's local values; `null` means missing |
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

### `expect`

- `read`: `{ items, skipped, uninspectable, duplicates? }`.
  - `items`: `[{ cipher, id, value, source }]`, sorted by `id`, with `source`
    one of `field`, `notes`, `login-password`, `note-body`. `value` is the
    decoded secret: base64 is decoded, and binary values are written as
    `"base64:<b64>"`. An optional `attributes` (object, name to value) lists
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

## Reason codes

Used in `expect.read.skipped[].reason`.

| Code | Meaning |
|---|---|
| `wrong-type` | The cipher is neither a login nor a secure note |
| `encoding-on-user-source` | An encoding mark sits on a value the user typed (such as the login password) |
| `unknown-location` | The `{ns}:location` mark names a location that does not exist |
| `unknown-encoding` | The `{ns}:encoding` mark names an encoding that does not exist |
| `invalid-id` | The `{ns}:id` mark is not a valid identifier |
| `reserved-id` | The `{ns}:id` mark uses a reserved identifier |
| `view-password-hidden` | An organization hides the password from this user |
| `organizations-off` | The cipher belongs to an organization and organizations are disabled |
| `undecryptable` | A string needed to inspect the cipher failed to decrypt |
| `newer-format` | The mark was written by a newer data model than this tool supports |
