# rosec-sops

A native rosec provider. The store is a **sops-encrypted file tree**: one file
per item, encrypted by `sops`.

On this host the recipient is a YubiKey age identity. The age identity file is
`~/.config/sops/age/keys.txt`, so the hardware token is the unlock. There is no
password prompt, and `unlock` proves the token works before it reports success.

## Layout

```text
<root>/.sops.yaml                          optional sops creation rules
<root>/<collection>/<item-id>.sops.yaml    one item, sops-encrypted YAML
<root>/<collection>/_meta.meta.yaml        collection label (optional)
<root>/<collection>/.superseded-…          archived, superseded copy
<root>/.conflicts/<collection>/<id>.md     plaintext conflict marker (no secrets)
```

The plaintext document inside each file:

```yaml
label: github.com
attributes:
  rosec:type: login
  username: user
secrets:
  password: hunter2
binary_secrets:          # only when a value is not UTF-8, standard base64
  blob: AP+AQQ==
created: 2026-11-14T18:02:11.000000000Z
modified: 2026-11-14T18:41:09.417000000Z
host: host-a
revision: 7
version: 1
```

- `created` and `modified` are RFC 3339 on write. A bare Unix epoch is accepted
  on read.
- `revision` counts writes. `host` names the writer, taken from the kernel
  hostname (not `$HOSTNAME`, which a stale shell can export).
- `version` is the item schema version. A missing field means version 1; a
  newer version is refused on read instead of being rewritten without its newer
  fields.
- `secrets` is a named map (`password`, `private_key`, `totp`, ...) of UTF-8
  text. A value that is not UTF-8 is stored as standard base64 under
  `binary_secrets` and comes back byte for byte — binary secrets are supported.

**Collection labels.** A collection is a directory, and its directory name is
its label. Only a collection whose label differs from the directory name gets a
`_meta.meta.yaml`. An ordinary store therefore holds item files only, and an
unreadable meta file just falls back to the directory name. The
`_meta.sops.yaml` name written by an earlier build is still read as a meta file,
never as an item.

**Item ids.** A file name is the item id plus `.sops.yaml`. New ids are
**random** (`item-` plus 16 random bytes in hex). They are not derived from the
secret: the store is synced as plaintext file names, so a hash of the secret
would let anyone who sees the store confirm a guess of a low-entropy password
without the YubiKey. The trade-off is that the file name no longer says what the
item contains; the label and the attributes are the readable hints.

The daemon sees bare ids for the largest collection (ties by name). It sees
`<collection>/<id>` for the other collections. Aliases are the daemon's
concern. The provider has no alias API.

## Configuration

```toml
[[provider]]
id   = "sops"
kind = "sops"
path = "~/Nextcloud/rosec-store"

[provider.options]
key_file      = "~/.config/sops/age/keys.txt"   # default
age_recipient = "age1yubikey1…"                 # optional
sops_binary   = "sops"                          # default
probe_timeout_seconds = 30                      # default
```

| Option                  | Required | Default                       | Meaning                                   |
| ----------------------- | -------- | ----------------------------- | ----------------------------------------- |
| `path`                  | yes      | —                             | Store root                                |
| `key_file`              | no       | `~/.config/sops/age/keys.txt` | Exported as `SOPS_AGE_KEY_FILE`; the `direct` identity, and the master's key by default |
| `age_recipient`         | no       | —                             | Recipients for new and changed files      |
| `sops_binary`           | no       | `sops`                        | The `sops` executable                     |
| `probe_timeout_seconds` | no       | `30`                          | Upper bound for the unlock decrypt probe  |

All paths accept a `~/` prefix. They must be absolute after expansion. A
malformed `age_recipient` is rejected at startup, so a typo cannot silently fall
back to the sops config.

## Recipients, two modes

### `age_recipient` set

Every new file is encrypted to all listed recipients, so a shared store stays
readable on each host with that host's own YubiKey:

```toml
age_recipient = "age1yubikey1…host-a,age1yubikey1…key-b"
```

An **update** encrypts to the **union** of this list and the recipients already
recorded in the file's header. A configured single recipient therefore never
narrows a file that was written to three: the update keeps all four. The header
recipients are public, so reading them needs no key.

### `age_recipient` unset

`sops --encrypt` runs without `--age`, and the creation rules of the `.sops.yaml`
in the store root decide the recipients:

```yaml
# <root>/.sops.yaml
creation_rules:
  - path_regex: .*\.sops\.yaml$
    age: age1yubikey1…,age1yubikey1…
```

This is the mode to choose for a store inside a repository that already has a
`.sops.yaml`. An update keeps the recipients the file already has. With no
matching rule the first write fails cleanly with `no encryption keys: neither
age_recipient nor a matching creation rule` and stores nothing.

The rule is matched against the name `rosec-encrypt-input.sops.yaml`, because
sops matches `path_regex` against the file it is told it is reading. A rule
keyed on `.*\.sops\.yaml$` works; a rule that only matches your own naming scheme
does not. Prefer omitting `path_regex` when in doubt.

## Encryption

Every encryption and decryption shells out to `sops`:

```text
SOPS_AGE_KEY_FILE=<key_file> sops --encrypt [--age <recipients>] \
    --input-type yaml --output-type yaml
SOPS_AGE_KEY_FILE=<key_file> sops --decrypt \
    --input-type yaml --output-type yaml <file>
```

There is no GPG step and no network access. No age key enters the process.

Writes go to a hidden temporary file in the same directory. The file is
fsynced, then renamed over the target. A reader sees the old file or the whole
new file, never a partial one. The temporary file is removed on every error path.

Reads are cached by `(mtime, size, sha256)` of the ciphertext. The hash is
computed on every read, so a rewrite that keeps the time and length is still
detected. Decryption, the step that may need the YubiKey, runs only when that
key changes.

**Error messages never quote sops output.** sops quotes document content in its
stderr, and a malformed document can make it quote plaintext. Every error
carries a classified reason (`decryption failed: the identity in key_file cannot
open this file`, `document could not be parsed`, ...) plus the exit code, never
the stderr text. A test feeds a crafted sops error containing a secret through
the whole error path.

## Store mode (always explicit)

Every store records **how its item files are encrypted** in a plaintext file
`<root>/.rosec-store.yaml`:

```yaml
version: 1
mode: direct   # or derived
```

| Mode      | Item files encrypted to                                   | Unlock cost                          |
| --------- | --------------------------------------------------------- | ------------------------------------ |
| `direct`  | the unlock keys themselves (the YubiKey recipient)         | one token operation per file decrypt |
| `derived` | a derived sops identity (see [Unlock once](#unlock-once))  | one token operation per **session**  |

**There is no default.** A store without this file, or with a missing or
unknown `mode`, is refused:

```text
error: sops store config: store `…` has no mode: `.rosec-store.yaml` is missing or has
no valid `mode`. The store mode is always explicit — run `rosec-sops --store … store
init --mode direct|derived`
```

The provider refuses to unlock, read or write such a store, and nothing is
written implicitly. The mode is also checked against the configuration:
`derived` requires `identity_file`, `direct` forbids it. A mismatch is a
configuration error, never a silent guess.

`rosec-sops store init --mode <direct|derived>` writes the metadata of an
existing store:

- `--mode direct` adopts a store that already holds items encrypted to the
  unlock keys (the behaviour of every store written before this option
  existed).
- `--mode derived` only records the mode; `rosec-sops identity init` creates the
  derived identity afterwards.
- Two `store init` runs with the same mode are a no-op. A **different** mode is
  refused, `--force` included: every existing item file was written for the
  other mode.

**The mode never changes in place.** The only supported way to change it is a
migration into a new store — see [Migrating a store](#migrating-a-store).

## Unlock once

A `derived` store costs **one YubiKey operation per session** instead of one per
file. The model has two layers.

### Layer 1: the store identity

The **store identity** is a plain age identity — an `AGE-SECRET-KEY-1…` line.
Every item file is encrypted to its **public recipient**, which is recorded in
plaintext in:

```text
<root>/.rosec-store-identity.recipient     one line, public, no secret
```

### Layer 2: the master file

The identity itself lives in a sops-encrypted master file:

```text
<root>/.rosec-store-identity.sops.yaml
```

```yaml
identity: ENC[AES256_GCM,…]
sops:
  age:
    - recipient: age1yubikey1…
```

Its recipients are the **unlock group**, chosen by the creation rule of the
store's `.sops.yaml` that matches `.rosec-store-identity.sops.yaml`. That rule
may use `age:`, `pgp:`, `kms:`, `hc_vault:` or any other sops key service, so
any sops mode works as the unlock. Adding or removing an unlock key is
`sops updatekeys` on this one file — it never touches an item.

### `.sops.yaml`: the master rule comes FIRST

```yaml
creation_rules:
  # 1. the master file: its recipients are the unlock group.
  - path_regex: ^\.rosec-store-identity\.sops\.yaml$
    age: age1yubikey1…host-a,age1yubikey1…key-b
  # 2. the items: encrypted to the derived identity only.
  - path_regex: .*\.sops\.yaml$
    age: age1…   # the derived recipient printed by `identity init`
```

**Order is load bearing.** sops applies the **first** matching rule, and the
item rule `.*\.sops\.yaml$` also matches the master file name. With the two
rules reversed, an `identity init` wraps the master to the item recipient — a
master nobody can open, silently. A test covers exactly that mistake.

Both YubiKeys belong in the master rule, comma-separated, so either host can
unwrap the store. A paper or offline recovery key may be added to the same list;
it is ordinary age, so it is unwrapped with `age -d`.

### The CLI

```sh
rosec-sops identity init [--force]   # derive the identity, write master + sidecar
rosec-sops identity show             # recipient, paths, runtime state; no decryption
rosec-sops identity rewrap           # re-wrap the master to the current rule
rosec-sops identity rekey            # new identity, every item re-encrypted
rosec-sops identity migrate          # one-time: direct items -> derived identity
rosec-sops store show                # the recorded mode
```

- `init` refuses to overwrite an existing master without `--force`, and warns
  that overwriting leaves every existing item unreadable (they belong to the
  old identity). It prints only the **public** derived recipient and a
  ready-to-paste `.sops.yaml` snippet.
- `show` prints the sidecar recipient, the master path, the unlock key file,
  the runtime path and whether a runtime identity exists.
- `rewrap` runs `sops updatekeys --yes <master>` with cwd = the store root, so
  the master rule decides the new set. It does not change the derived identity:
  **no item is re-encrypted.**
- `rekey` rotates the derived identity and re-encrypts every item. This is the
  strong revocation: the old identity stops reading everything written after
  it.
- `migrate` moves a store whose items were encrypted to the unlock keys onto
  the derived identity, once. It decrypts with `key_file` and re-encrypts to the
  sidecar's recipient.
- No command ever prints a secret. The derived identity only travels between
  the master, the runtime file and a `sops` child process.

### The provider options

```toml
[provider.options]
path                = "~/…/rosec-storage"
identity_file       = "<store>/.rosec-store-identity.sops.yaml"
identity_key_file   = "~/.config/sops/age/keys.txt"   # only to decrypt the master
runtime_identity_file = "$XDG_RUNTIME_DIR/rosec/store-identity.age"  # default
key_file            = "~/.config/sops/age/keys.txt"   # the local unlock identity
age_recipient       = "age1…"                         # the derived recipient
```

| Option                   | Required        | Default                                    | Meaning                                        |
| ------------------------ | --------------- | ------------------------------------------ | ---------------------------------------------- |
| `identity_file`          | `derived` only  | —                                          | The master file; its presence selects `derived` |
| `identity_key_file`      | no              | `key_file`                                 | Identity used **only** to decrypt the master    |
| `runtime_identity_file`  | no              | `$XDG_RUNTIME_DIR/rosec/store-identity.age` | Session cache, `/tmp/rosec-<uid>/…` when unset |

`unlock` then:

1. reads the store mode and checks it against the configuration;
2. reuses `runtime_identity_file` when it is non-empty and holds an
   `AGE-SECRET-KEY-1` line — **no token operation at all**;
3. otherwise decrypts the master **once**, bounded by `probe_timeout_seconds`:
   `sops --decrypt --extract '["identity"]' …` with
   `SOPS_AGE_KEY_FILE=<identity_key_file or key_file>`;
4. writes the identity atomically to `runtime_identity_file`, mode `0600` below
   a `0700` directory;
5. points every item operation at that runtime file;
6. probe-decrypts one store item; on failure the runtime file is removed, the
   key file is reset and `AuthFailed` is returned.

`lock` removes the runtime file, resets the effective key file to `key_file`
and clears the decrypted-document cache.

### Security model

- The derived identity is a **secret on disk** for the length of the session,
  in `$XDG_RUNTIME_DIR` (a tmpfs, mode `0600`, below a `0700` directory). It is
  removed on `lock`, which `rosec` runs when the session ends.
- The trade is explicit: within one unlocked session, a local process that can
  read the runtime file can read the store without the YubiKey. That is the
  point of the feature — one touch instead of hundreds — and the runtime file
  dies with the session.
- The **master file is safe to sync.** It is ciphertext; only the unlock group
  can open it. The public sidecar is public by construction.
- The YubiKey stays the root of trust: it decides whether the master opens.
- **Losing every unlock key loses the store.** There is no other copy of the
  derived identity. Keep at least two independent unlock keys; consider a
  paper recovery key in the master rule.
- `rewrap` and `rekey` are different tools:
  - `rewrap` — same derived identity, different unlock keys. Cheap, touches one
    file.
  - `rekey` — new derived identity, every item re-encrypted. Expensive, and the
    only way to revoke the old *derived* identity.

### Runbook: migrate an existing store

```sh
# 1. Extend the store's .sops.yaml with the master rule (FIRST) and keep the
#    current item rule for now.
# 2. Record the mode and create the derived identity.
rosec-sops --store <store> store init --mode derived
rosec-sops --store <store> identity init
# 3. Point the item rule at the printed derived recipient.
# 4. Re-encrypt the existing items.
rosec-sops --store <store> identity migrate
# 5. Set identity_file and age_recipient in the provider options, then unlock.
```

`migrate` prints how many files it rewrote. A file it could not decrypt is
listed and left untouched, so a partial migration is visible, not silent.

### Runbook: add or remove an unlock key

```sh
# 1. ADD the new key to the master rule in .sops.yaml.
rosec-sops --store <store> identity rewrap
# 2. verify the new key opens the master on its own host, then
# 3. REMOVE the old key from the rule and rewrap again.
rosec-sops --store <store> identity rewrap
```

Do it in that order. A single rewrap from a rule with no key in common with the
file fails cleanly and leaves the master untouched, but doing it in one step on
a rule you also mistyped is how a store gets locked out.

### Runbook: rotate the derived identity (`rekey`)

```sh
rosec-sops --store <store> identity rekey
# then: item rule age -> the printed recipient, and the nix module's
# age_recipient -> the same value.
```

`rekey` needs the old identity: it uses the valid runtime file when present,
else the old master through `key_file`. It re-encrypts every item first, then
writes the new master, sidecar and runtime file. A second `rekey` rotates again.

## Migrating a store

`rosec-sops store migrate --from <src> --to <dst> [--mode direct|derived]` copies
a store into a new one and is the **only** supported way to change the mode:

```sh
rosec-sops --store <src> store migrate --from <src> --to <dst> --mode derived
```

- The destination must be new, or hold nothing but its own store metadata, its
  master file, its recipient sidecar and `.sops.yaml`; `--force` accepts a
  populated one (files are then protected by `--overwrite`).
- `--mode` initialises the destination metadata when it has none; otherwise the
  destination must already carry a valid mode. A `derived` destination needs
  `identity init` first.
- Every item is decrypted with the source key/identity and re-encrypted for the
  destination, so item ids, collections, labels, timestamps and revisions
  survive.
- Conflict archives (`.superseded-*`) and `.conflicts/` markers are **not**
  copied. A store with an unresolved conflict is refused: resolve it first, or
  a losing value would either be smuggled along or silently dropped.
- The source is never modified. Run the daemon against one store at a time.

## Conflict rule (placeholder)

For one item id, the provider reads the canonical `<id>.sops.yaml` and every
Syncthing conflict copy of the same id in the same collection
(`<id>.sops.yaml.sync-conflict-*` or `<id>.sync-conflict-*.sops.yaml`).

**The copy with the latest `modified` wins.** A conflict copy wins over the
canonical file whenever its `modified` is later. On a full tie (equal
`modified`, equal `host`, equal `revision`) the canonical file wins. An item
that fails to decrypt is skipped with a warning.

A read never changes the store. A write does:

1. the merged document is written to the **canonical** file, whatever copy was
   served;
2. every other copy of that id — including the served copy when it was a
   conflict copy — is renamed to
   `.superseded-<id>.<nanos>-<host>.sops.yaml`, a dotfile that no longer
   resolves as an item;
3. the archive path is logged at `warn`;
4. a plaintext conflict marker is written to
   `<root>/.conflicts/<collection>/<id>.md`, so the conflict is visible without
   a key — see [Conflict markers](#conflict-markers).

The archive is never deleted by a write: it keeps the value that lost, for
review. Deleting the item removes every copy and archive of that id, and its
marker.

This rule is a placeholder. It can lose a secret when two hosts edit at once. It
depends on wall-clock agreement. The follow-up task is
`docs/tasks/2026-11/rosec-conflict-resolution/definition.md` in the nix-configs
repository.

## Conflict markers

The provider archives a losing copy instead of deleting it, so nothing is lost
silently — but an archived dotfile is easy to miss. Every archiving write
therefore also writes a **plaintext, secret-free** marker:

```text
<root>/.conflicts/<collection>/<item-id>.md
```

```markdown
---
item: item-a26e0ed2f8fc642f6b8d078338ca55e0
collection: default
label: github.com
winner: default/item-a26e0ed2f8fc642f6b8d078338ca55e0.sops.yaml
losers:
- file: default/.superseded-item-a26e0ed2f8fc642f6b8d078338ca55e0.01794687082643598386-host-a.sops.yaml
  modified: 2026-11-14T18:30:00Z
  host: otherhost
  revision: 2
  secrets:
  - password
winner_meta:
  file: default/item-a26e0ed2f8fc642f6b8d078338ca55e0.sops.yaml
  modified: 2026-11-14T18:00:00Z
  host: host-a
  revision: 3
  secrets:
  - password
written: 2026-11-14T20:00:00Z
attributes:
  username: user
hint: Run `rosec-sops conflicts show <item-id>`, then `rosec-sops conflicts resolve <item-id> --keep <winner|loser|file>`.
---

# rosec conflict: github.com (`item-a26e…`)

… a human-readable body with the same facts and the resolution hint …
```

What it holds: the item id, the collection and its label, the canonical winner,
every archived loser, and the `modified`/`host`/`revision` triple of each, the
recording time, the public attributes and one resolution hint. Secret **names**
are listed; secret **values never are** — the marker is built from fields that
hold no value, and a guard drops the attributes when the rendered text happens
to quote one.

Lifecycle:

- one marker per item id; a later conflict **replaces** it, so it always
  describes the latest set of archived copies;
- a delete of the item removes the marker with the files;
- `rosec-sops conflicts resolve` removes it.

The marker directory is plaintext and outside every collection, so a host-side
watcher needs no key: watching `<root>/.conflicts` is enough to notify the user.

The provider also flags the item for clients: `rosec:sops-unresolved-conflict`
is present while a marker exists, so one search finds every unresolved
conflict.

## `rosec-sops conflicts` CLI

The crate also ships a `rosec-sops` binary. It needs **no daemon** and needs no
decryption for `list` and `show`; `resolve` only decrypts when an identity file
is present.

```sh
rosec-sops conflicts list [--json]
rosec-sops conflicts show <item-id|collection/item-id> [--json]
rosec-sops conflicts resolve <item-id|collection/item-id> --keep <winner|loser|file>
```

- `list` — every marker: item, collection, label, winner, losers, hosts,
  timestamps. `--json` gives one object per conflict for a script or a watcher.
- `show` — the marker plus a plaintext overview, and whether each recorded file
  is still on disk. Never prints a secret value.
- `resolve --keep winner` — keep the canonical file, **delete** the archived
  losers, remove the marker.
- `resolve --keep loser` — keep the newest archived loser: it is renamed onto
  the canonical path (an atomic replace) and the previous canonical file is
  archived, never deleted. The marker is removed.
- `resolve --keep <file>` — the same, for a file named by `show`: an absolute
  path, a path relative to the store root, or a bare file name.
- An unknown id, an unknown file, or a marker that names another collection is
  refused **before** anything changes. Every command prints exactly which file
  it kept, deleted or archived.

Store discovery, the same as the provider:

| Source                          | Meaning                                             |
| ------------------------------- | --------------------------------------------------- |
| `--store <path>`                | Store root; the identity comes from `SOPS_AGE_KEY_FILE` |
| `ROSEC_SOPS_STORE`              | Same, as an environment default                     |
| `--config <file>`               | rosec config file (default `$XDG_CONFIG_HOME/rosec/config.toml`) |
| `ROSEC_CONFIG`                  | Same, as an environment default                     |
| `--provider <id>`               | Which `kind = "sops"` entry, when the config has several |

From the config file the CLI reads `path` and `provider.options.key_file`, so it
uses exactly the store and identity the daemon uses.

### Resolution workflow

1. A write archived a copy: the daemon log carries a `warn` with the archive
   path and the marker, and the item is flagged.
2. `rosec-sops conflicts list` on any host that syncs the store.
3. `rosec-sops conflicts show <item-id>` to compare revisions, hosts and times.
   To compare values, decrypt both files yourself:
   `sops --decrypt <archive>`.
4. `rosec-sops conflicts resolve <item-id> --keep winner|loser|<file>`.
5. The marker is gone; the next `list` prints `no conflicts`.

The real merge (per-field merge, keep-both secrets, clock-independent ordering)
is the follow-up task in the nix-configs repository:
`docs/tasks/2026-11/rosec-conflict-resolution/definition.md`.


## Locked behaviour

`unlock` verifies three things:

1. the `sops` binary runs;
2. the age identity file exists;
3. **one store file decrypts** — a collection meta file when present, else the
   smallest item file, under `probe_timeout_seconds`.

Step 3 is what makes "the YubiKey is the unlock" a checked claim. A token in the
wrong slot, a revoked recipient, or a `keys.txt` holding another identity fails
`unlock` with `AuthFailed` instead of unlocking and then failing on every read.
An empty store has nothing to prove and unlocks after the first two steps.

`lock` drops the decrypted-document cache.

While the provider is locked, `list_items`, `search`, reads and writes all return
`ProviderError::Locked`. The daemon maps that to `RefreshOutcome::Locked` and
keeps its previous view; an empty list would be a complete refresh of zero items
and would wipe every sops item from the cache.

The unlock password field is optional and ignored. `rosec unlock` accepts a bare
Enter.

## Attributes

`rosec:type` and `rosec:totp` are reserved by `rosec-core`. This provider also
manages four attributes of its own:

| Attribute                        | Meaning                                              |
| -------------------------------- | ---------------------------------------------------- |
| `collection`                     | Collection label of the item                         |
| `rosec:collection-dir`           | Collection directory that holds the item's file      |
| `rosec:sops-conflict`            | Present when the served copy is a conflict copy      |
| `rosec:sops-unresolved-conflict` | Present while a conflict marker waits for a decision |

None of them may come from a client. The provider strips them from `attributes`
on create and update and stamps the values itself, so the Secret Service layer
can echo a full attribute map back on a read-modify-write. A forged
`rosec:sops-conflict`, `rosec:sops-unresolved-conflict` or
`rosec:collection-dir` is discarded, and a stored `rosec:type` survives an
attribute replacement.

## Value mapping

rosec secrets are bytes. A UTF-8 value is stored as text under `secrets`; a
value that is not UTF-8 is stored as standard base64 under `binary_secrets`.
Both round-trip exactly, including NUL bytes.

Only `Capability::Write` is declared. SSH keys and TOTP seeds in the store are
not turned into an agent key or a TOTP file — that is a deliberate scope
decision, not a missing feature.

## Directory permissions

Item files and meta files are written `0600`. Collection directories are created
with the default `0755`, because directory names are collection names, not
secrets, and a syncing client should be able to read the tree.

## Tests

Run inside the devenv shell, which provides `sops` and `age-keygen`:

```sh
devenv shell -- cargo test -p rosec-sops
devenv shell -- cargo clippy -p rosec-sops --all-targets -- -D warnings
devenv shell -- cargo test -p rosec-secret-service --test sops_provider_secret_tool
```

The first suite uses a temporary store and a generated age key. It covers
create, read, update, delete, search, random ids, binary secrets, collection
labels, locking, path and recipient validation, both recipient modes, the
recipient-union rule, the unlock probe, error redaction, and a Syncthing
conflict copy where the newer `modified` wins, the loser stays on disk, and a
write archives it without breaking resolution.

The conflict-marker tests cover the whole lifecycle: a conflict writes the
marker, the provider flags the item, `list` finds it, `resolve` removes it and
the flag, and a second resolve refuses. They also cover resolve keeping the
winner, keeping the loser, keeping a named file, refusing an unknown id or file
without touching the store, the marker disappearing with a deleted item, and a
marker holding no secret value for a store that stores a known one. An
integration test (`tests/cli.rs`) drives the real `rosec-sops` binary through
`list --json`, `show` and `resolve --keep loser` and greps every output for the
known secret.

The second suite runs a private D-Bus session with the real `secret-tool`. It
covers store, lookup, search and clear of a **non-empty** secret through the
Secret Service.

For a real-hardware run, use the example (it needs the plugged YubiKey; it
writes to the store you name and deletes the item again):

```sh
devenv shell -- cargo run -p rosec-sops --example yubikey_smoke -- \
  ~/Nextcloud/rosec-store \
  ~/.config/sops/age/keys.txt \
  age1yubikey1…
```

Add `--dry-run` to use a fresh temporary store instead, so the hardware path can
be exercised without touching the synced tree.
