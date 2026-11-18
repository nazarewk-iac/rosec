{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

# Rust development shell for the rosec workspace.
#
# This shell builds with `cargo` — it performs no Nix build of the project.
# The workspace `rust-version` is 1.96 and the edition is 2024.
#
# The `wasm32-wasip1` target is best-effort: devenv forbids `targets` together
# with the nixpkgs channel, so the shell does not install it. Only the excluded
# WASM provider crates (`rosec-bitwarden-*`, `rosec-gnome-keyring`,
# `rosec-keepassxc-file`, `rosec-protonpass`) need it. The planned custom
# provider is native, so this shell does not cover it; run
# `rustup target add wasm32-wasip1` in a rustup-managed toolchain if you need
# to build those WASM providers.
#
# Use the flake output `packages.rosec` when you want the installed binary tree;
# use this shell for fast edit/compile/test cycles.
{
  packages = [
    # Provider development and test fixtures.
    pkgs.age
    pkgs.sops
    pkgs.git

    # Build-time helpers: `pkg-config` drives the `-sys` crates, `clang` drives
    # the bindgen crates, `zstd` covers the compressed vault paths.
    pkgs.pkg-config
    pkgs.clang
    pkgs.zstd

    # Link-time libraries.
    pkgs.openssl
    pkgs.pam
    pkgs.fuse3
    pkgs.libfido2
    pkgs.pcsclite
    pkgs.libxkbcommon
    pkgs.wayland
    pkgs.dbus
  ];

  # `dbus-daemon` and `dbus-launch` drive the Secret Service test harness.
  env.PKG_CONFIG_PATH = lib.makeSearchPath "lib/pkgconfig" [ (lib.getDev pkgs.openssl) ];

  languages.rust = {
    enable = true;
    # Default `channel = "nixpkgs"`; current nixos-unstable carries Rust 1.99,
    # which satisfies the 1.96 MSRV without adding rust-overlay as an input.
  };

  enterShell = ''
    echo "rosec dev shell — $(rustc --version)"
  '';

  scripts.build.exec = "cargo build -p rosecd";
  scripts.test-ss.exec = "cargo test -p rosec-secret-service";
  scripts.check-all.exec = "cargo check --workspace";
}
