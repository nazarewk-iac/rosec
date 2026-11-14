{
  description = "rosec — secrets daemon implementing the freedesktop.org Secret Service API";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      # Adapted from nixpkgs `pkgs/by-name/ro/rosec/package.nix`: `rosecCore`
      # plus `pam_rosec`, joined into one symlinkJoin profile. The WASM provider
      # packages are omitted; the planned custom provider is native.
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs)
            lib
            stdenv
            rustPlatform
            autoPatchelfHook
            symlinkJoin
            pam
            dbus
            pkg-config
            wayland
            libxkbcommon
            zstd
            ;

          # Single source of truth: a release bump in `Cargo.toml` must not
          # leave the package labelled with the old version.
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

          src = self;

          rosecPam = stdenv.mkDerivation {
            pname = "pam_rosec";
            inherit version src;
            # `src = self` is a plain source tree, not a `fetchFromGitHub` result,
            # so it has no `.name` to build a sourceRoot from.
            setSourceRoot = "sourceRoot=$(echo */contrib/pam)";

            buildInputs = [ pam ];

            makeFlags = [
              "PREFIX=$(out)"
              "ROSEC_PAM_UNLOCK_PATH=${rosecCore}/libexec/rosec/rosec-pam-unlock"
            ];

            installPhase = ''
              runHook preInstall
              install -Dm755 pam_rosec.so "$out/lib/security/pam_rosec.so"
              runHook postInstall
            '';
          };

          rosecCore = rustPlatform.buildRustPackage {
            pname = "rosec-unwrapped";
            inherit version src;

            # `src = self` carries Cargo.lock. The lock pins three crates to a
            # git branch (`RustCrypto/SSH`), so they need explicit vendor hashes.
            # `outputHashes` maps a crate `name-version` to the hash of the whole
            # fetched git tree; all three crates share one commit, so one hash
            # serves all of them (commit 68e8589194942f4eedcdbf86669076073c997d32).
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "ssh-cipher-0.2.0" = "sha256-QxERWdCppY/bwpYvTtweQFEC8TtYhlFqypIKnaDy79I=";
                "ssh-encoding-0.2.0" = "sha256-QxERWdCppY/bwpYvTtweQFEC8TtYhlFqypIKnaDy79I=";
                "ssh-key-0.6.7" = "sha256-QxERWdCppY/bwpYvTtweQFEC8TtYhlFqypIKnaDy79I=";
              };
            };

            nativeBuildInputs = [
              autoPatchelfHook
              dbus
              pkg-config
            ];

            runtimeDependencies = [
              libxkbcommon
              wayland
            ];

            buildInputs = [
              stdenv.cc.cc.lib
              zstd
            ];

            nativeCheckInputs = [ dbus ];

            # Two things the sandbox lacks:
            #  * `zbus::Connection::session()` needs `DBUS_SESSION_BUS_ADDRESS`,
            #    so start one private session bus for the whole check phase;
            #  * the test-support `PrivateBus` helper spawns bare
            #    `dbus-daemon --session`, which reads `/etc/dbus-1/session.conf`
            #    regardless of that variable, so wrap it with an explicit
            #    `--config-file`.
            preCheck = ''
              ${dbus}/bin/dbus-daemon --config-file=${dbus}/share/dbus-1/session.conf \
                --fork --print-address=1 --print-pid=1 > bus.txt
              { read -r address; read -r bus_pid; } < bus.txt
              export DBUS_SESSION_BUS_ADDRESS="$address"
              echo "session bus at $address (pid $bus_pid)"

              mkdir -p test-bin
              cat > test-bin/dbus-daemon <<'EOF'
              #!${pkgs.runtimeShell}
              # Drop the implicit default config path that `--session` uses.
              args=()
              for a in "$@"; do
                [ "$a" = "--session" ] && continue
                args+=("$a")
              done
              exec ${dbus}/bin/dbus-daemon --config-file=${dbus}/share/dbus-1/session.conf "''${args[@]}"
              EOF
              chmod +x test-bin/dbus-daemon
              export PATH=$PWD/test-bin:$PATH

              # rosec-vault sidecar tests require a writable xdg data directory,
              # and the wasmtime-based tests write a cache under `$HOME/.cache`.
              export XDG_DATA_HOME=$TMPDIR/xdg-data
              export HOME=$TMPDIR/home
              mkdir -p "$HOME" "$XDG_DATA_HOME"
            '';

            postInstall = ''
              mkdir -p $out/libexec/rosec
              mkdir -p $out/lib/rosec/providers
              mkdir -p $out/share/dbus-1/system.d
              mkdir -p $out/share/systemd/user

              mv $out/bin/rosec-pam-unlock $out/libexec/rosec/

              # `rosec enable` writes the D-Bus, systemd user unit and xdg portal
              # registrations into $XDG_CONFIG_HOME and $XDG_DATA_HOME, which are
              # redirected into the output here.
              XDG_CONFIG_HOME=$out/lib XDG_DATA_HOME=$out/share $out/bin/rosec enable
            '';

            meta = {
              description = "Secrets daemon implementing the freedesktop.org Secret Service API with modular backend providers";
              homepage = "https://github.com/jmylchreest/rosec";
              license = lib.licenses.mit;
              platforms = lib.platforms.linux;
              mainProgram = "rosec";
            };
          };
        in
        rec {
          rosec = symlinkJoin {
            name = "rosec-${version}";
            paths = [
              rosecCore
              rosecPam
            ];
            inherit (rosecCore) meta;
            passthru = { inherit rosecCore rosecPam; };
          };
          default = rosec;
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
