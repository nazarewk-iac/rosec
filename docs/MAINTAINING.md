# Maintaining this fork

This is the `nazarewk-iac/rosec` fork. It adds one native provider to upstream rosec:
`rosec-sops`, a Secret Service backend whose store is a **sops-encrypted file tree**. The fork
also carries a `devenv` shell and a `flake.nix` package output for local development.

The rule for this fork: **be additive**. New files live in new paths. Only the absolutely
necessary upstream code changes are made, so the overlapping surface stays small and a rebase
stays cheap.

## Remotes and bookmarks

| Remote        | URL                                   | Role     |
| ------------- | ------------------------------------- | -------- |
| `origin`      | `github.com/jmylchreest/rosec`        | upstream |
| `nazarewk-iac` | `github.com/nazarewk-iac/rosec`      | fork     |

The fork uses one **bookmark per patch**, joined into `main`:

- `sops-provider` — the native provider and its tests, cut **directly from upstream**; its only
  ancestor is `origin/main`;
- `devenv` — the devenv shell, the flake package and this document, also cut from upstream;
- `main` — the integration line: a two-parent commit of the two bookmarks above.

`sops-provider` must stay on the upstream line alone. If it carries the merge (because it was
advanced to `main` by mistake), a pull request opened from it drags the devenv and flake files
along. Check the invariant before opening a PR:

```sh
jj log -r 'sops-provider ~ ::origin/main' --no-graph   # must print nothing
```

The nix-configs consumer pins `main`'s commit id, so `main` is the only bookmark that must move
for a dependency bump.

## Development

Use the devenv shell. It provides Rust (>= 1.96), the system libraries the workspace needs
(`dbus`, `openssl`, `pam`, `fuse3`, `libfido2`, `pcsclite`, `libxkbcommon`, `wayland`), and
`sops`/`age` for the provider.

```sh
devenv shell -- cargo check --workspace
devenv shell -- cargo test -p rosec-sops -p rosecd
devenv shell -- cargo clippy -p rosec-sops --all-targets -- -D warnings
devenv shell -- cargo fmt --check
```

The flake package reads its version from the workspace `Cargo.toml`, so a release bump cannot
mislabel it. It builds the workspace the way the nixpkgs recipe does. Run it occasionally to
confirm the package still syncs:

```sh
nix build .#rosec
./result/bin/rosec --version
```

The provider's real-hardware smoke test is an example. It needs a YubiKey age identity:

```sh
devenv shell -- cargo run -p rosec-sops --example yubikey_smoke
```

The `secret-tool` integration test starts its own private session bus; it never touches the live
session bus.

## The provider

`rosec-sops/` is the provider crate. It implements `rosec_core::Provider` plus the `write`
capability and is registered in `rosecd/src/main.rs::build_providers` as kind `sops`.

Upstream code changes — keep this list **at three files plus the lock**:

| File                | Change                                                                    |
| ------------------- | ------------------------------------------------------------------------- |
| `Cargo.toml`        | workspace member `rosec-sops` + the `serde_yaml` workspace dependency      |
| `rosecd/Cargo.toml` | dependency on `rosec-sops`                                                 |
| `rosecd/src/main.rs`| `build_providers` and the hot-reload `match` arms (startup **and** reload) |
| `Cargo.lock`        | generated; pure insertions (see below)                                     |

Do not add more upstream edits. In particular:

- `.gitignore` — `.devenv/` is listed in `.git/info/exclude`, which is local and never committed.
- `README.md` — the provider table stays upstream. `rosec-sops/README.md` documents the provider.
- `rosec-secret-service/Cargo.toml` — the `secret-tool` integration test lives in
  `rosec-sops/tests/secret_tool.rs` and reuses upstream's `tests/support/private_bus.rs` via
  `#[path]`, so `rosec-sops` carries `rosec-secret-service` and `zbus` as dev-dependencies.

`rosec-core` stays untouched: the `Provider` trait is the upstream extension point. Keep it
that way. If a change seems to need a `rosec-core` edit, stop and check whether the trait's
optional methods or the capabilities already cover it.

`rosecd` has **two** provider-construction matches: one in `build_providers` (startup) and one
in `reconcile_providers` (config hot-reload). Any new kind must appear in both; a kind present
only at startup is warning-logged and dropped on the first reload. The unit test
`sops_provider_builds_on_the_hot_reload_path` guards this.

### Keeping `Cargo.lock` small

The lock is **insertions only** over upstream: the four new packages (`rosec-sops`,
`serde_yaml`, `ryu`, `unsafe-libyaml`) and the `"rosec-sops"` edges. A plain `cargo` run in a
different resolver state rewrites ~10 existing packages' `windows-sys`/`getrandom` edges for no
version bump, which conflicts with every upstream lock change. After touching dependencies,
check the diff:

```sh
git diff --numstat origin/main -- Cargo.lock   # expect +51/-0
```

If it grew, restore `Cargo.lock` from upstream, add only the new dependency to the manifest, and
let `cargo metadata` (no `--locked`) insert the minimum. Confirm with
`cargo metadata --locked`, which fails when the lock does not match the manifests.

The provider's own documentation, the store layout, the conflict rule and the `rosec-sops`
conflict CLI are in `rosec-sops/README.md`.

## Update from upstream

```sh
repo="$(g-dir github.com/nazarewk-iac/rosec)"
cd "$repo"
jj git fetch --remote origin
```

Rebase each patch onto the new upstream line. Resolve conflicts in the patch, never on `main`.
Keep `sops-provider` a single commit whose parent is upstream:

```sh
jj rebase -s sops-provider -d origin/main
jj rebase -s devenv -d origin/main
```

Re-join the integration line. A new merge commit is expected; nothing is rewritten:

```sh
jj new devenv sops-provider -m "merge devenv and sops-provider"
jj bookmark set main -r @
jj new
```

Run the checks, then push the bookmarks:

```sh
devenv shell -- cargo test -p rosec-sops -p rosecd
devenv shell -- cargo clippy -p rosec-sops --all-targets -- -D warnings
devenv shell -- cargo fmt --check
nix build .#rosec

jj git push --remote nazarewk-iac --bookmark devenv --bookmark sops-provider --bookmark main
```

The commits are signed when the signing key is available. If the key is locked, a local commit
with `jj --config signing.behavior=drop` is acceptable, but re-sign before pushing if the
signature matters to the consumer.

## Upstream pull request

The provider patch is a candidate for upstream. The upstreamable part is the `rosec-sops` crate
plus the `rosecd` registration (startup and hot-reload arms); the devenv shell and the flake are
fork conveniences. Open the PR from the `sops-provider` bookmark, whose only ancestor is
`origin/main`, not from the fork's `main`.

## Conflict handling

The provider resolves a conflict by "latest `modified` wins" and never deletes the loser: it
archives every other copy of the item id as `.superseded-<id>.<nanos>-<host>.sops.yaml` and
writes a plaintext, secret-free marker under `.conflicts/<collection>/<id>.md`. The
`rosec-sops conflicts list|show|resolve` CLI lists the markers and resolves them.

The better conflict scheme is a separate task in the nix-configs repository:
`docs/tasks/2026-11/rosec-conflict-resolution/definition.md`.

## Host integration

The consumer side (the nix-configs repository) owns the systemd unit, the provider config, the
conflict notification and the migration. See `docs/rosec.md` in that repository.
