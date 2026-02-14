{
  description = "A Nix-flake-based Rust development environment with pre-commit shell hook";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks-nix.inputs.nixpkgs.follows = "nixpkgs";
    git-hooks-nix.url = "github:cachix/git-hooks.nix";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ {
    self,
    flake-parts,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [inputs.git-hooks-nix.flakeModule];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem = {
        pkgs,
        config,
        system,
        ...
      }: let
        /*
        Toolchain selection:
        - Load the Rust toolchain from `rust-toolchain.toml` so Nix and rustup
          users share the same channel/components.
        */
        rustPkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [inputs.rust-overlay.overlays.default];
        };
        toolchain = rustPkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustc = toolchain;
        cargo = toolchain;
        rustfmt = toolchain;
        clippy = toolchain;
        analyzer = toolchain;

        # Helpful extras—adjust to taste
        cargoComponents = with pkgs; [
          cargo-edit
          cargo-watch
          cargo-nextest
          cargo-audit
          pkg-config
        ];
      in {
        # Pre-commit hooks configuration (mirrors your Python setup’s style)
        pre-commit.settings = {
          # Anything listed as a hook will be made available to the devShell
          # via `enabledPackages`, which we include in packages below.
          hooks = {
            # Keep Nix files tidy
            alejandra.enable = true;

            # Rust format/lints
            rustfmt = {
              enable = true;
              packageOverrides = {
                cargo = toolchain;
                rustfmt = toolchain;
              };
            };
            clippy = {
              enable = true;
              packageOverrides = {
                cargo = toolchain;
                clippy = toolchain;
              };
            };

            # Optional: run a fast build check (uncomment if desired)
            # cargo-check.enable = true;

            # Optional: security audit (can be slower on large workspaces)
            # cargo-audit.enable = true;
          };
        };

        # Dev shell with shellHook installing pre-commit
        devShells.default = pkgs.mkShell {
          shellHook = ''
            # Ensure cargo/rustc/clippy all resolve from the same pinned toolchain.
            export PATH=${toolchain}/bin:$PATH
            ${config.pre-commit.installationScript}
            echo 1>&2 "Welcome to the development shell ($( ${rustc}/bin/rustc --version ))!"
            echo 1>&2 "  - rustc:   $(${pkgs.coreutils}/bin/printf '%s' "$(${rustc}/bin/rustc --version)")"
            echo 1>&2 "  - cargo:   $(${pkgs.coreutils}/bin/printf '%s' "$(${cargo}/bin/cargo --version)")"
            echo 1>&2 "  - clippy:  $(${pkgs.coreutils}/bin/printf '%s' "$(${clippy}/bin/cargo-clippy --version 2>/dev/null || echo 'available via cargo clippy')")"
            echo 1>&2 "  - rustfmt: $(${pkgs.coreutils}/bin/printf '%s' "$(${rustfmt}/bin/rustfmt --version)")"
          '';

          # Tools needed for your workflow, plus anything required by hooks.
          packages =
            config.pre-commit.settings.enabledPackages
            ++ [
              rustc
              cargo
              rustfmt
              clippy
              analyzer
            ]
            ++ cargoComponents;
        };
      };

      flake = {};
    };
}
