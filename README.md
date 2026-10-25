# dybw-core

The shared core of bwss (a Rust Secret Service daemon) and the Obsidian
plugin, both backed by Bitwarden. For now the repository holds only the
language-neutral conformance vectors: plaintext scenarios, a deterministic
generator that encrypts them, and the schemas that pin the formats. See
[`vectors/README.md`](vectors/README.md) for the formats.

## Vectors

Regenerate the encrypted scenarios from the sources:

```bash
uv run vectors/gen/gen.py build
```

Check that the committed files match what a build would produce (exit 1 and
a list of stale files otherwise):

```bash
uv run vectors/gen/gen.py check
```

Run the tests with:

```bash
uv run --with jsonschema --with pytest --with cryptography --with argon2-cffi pytest vectors/gen -q
```
