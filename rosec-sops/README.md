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
  username: kdn
secrets:
  password: hunter2
binary_secrets:          # only when a value is not UTF-8, standard base64
  blob: AP+AQQ==
created: 2026-11-14T18:02:11.000000000Z
modified: 2026-11-14T18:41:09.417000000Z
host: oams
revision: 7
```

- `created` and `modified` are RFC 3339 on write. A bare Unix epoch is accepted
  on read.
- `revision` counts writes. `host` names the writer, taken from the kernel
  hostname (not `$HOSTNAME`, which a stale shell can export).
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
path = "~/Nextcloud/drag0nius@nc.nazarewk.pw/important/rosec-storage"

[provider.options]
key_file      = "~/.config/sops/age/keys.txt"   # default
age_recipient = "age1yubikey1…"                 # optional
sops_binary   = "sops"                          # default
probe_timeout_seconds = 30                      # default
```

| Option                  | Required | Default                       | Meaning                                   |
| ----------------------- | -------- | ----------------------------- | ----------------------------------------- |
| `path`                  | yes      | —                             | Store root                                |
| `key_file`              | no       | `~/.config/sops/age/keys.txt` | Exported as `SOPS_AGE_KEY_FILE`           |
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
age_recipient = "age1yubikey1…oams,age1yubikey1…brys"
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
- file: default/.superseded-item-a26e0ed2f8fc642f6b8d078338ca55e0.01794687082643598386-oams.sops.yaml
  modified: 2026-11-14T18:30:00Z
  host: otherhost
  revision: 2
  secrets:
  - password
winner_meta:
  file: default/item-a26e0ed2f8fc642f6b8d078338ca55e0.sops.yaml
  modified: 2026-11-14T18:00:00Z
  host: oams
  revision: 3
  secrets:
  - password
written: 2026-11-14T20:00:00Z
attributes:
  username: kdn
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
  ~/Nextcloud/drag0nius@nc.nazarewk.pw/important/rosec-storage \
  ~/.config/sops/age/keys.txt \
  age1yubikey1q25g9xpunct74wnn29dgcgep78q666dkhpfg2flltg92fvyrew02j28464d
```

Add `--dry-run` to use a fresh temporary store instead, so the hardware path can
be exercised without touching the synced tree.
