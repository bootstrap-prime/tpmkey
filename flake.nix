{
  description = "Nix flake to pin everything in place for the rust dev env.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs@{ self, flake-utils, nixpkgs, rust-overlay, crane, ... }:
    flake-utils.lib.eachSystem [ flake-utils.lib.system.x86_64-linux flake-utils.lib.system.aarch64-linux ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
        rec {
          rust = (pkgs.rust-bin.selectLatestNightlyWith (toolchain:
            toolchain.default.override {
              extensions = [ "rust-src" "rustfmt" "rust-analyzer-preview" ];
            }));

          devShell = let
            cargo-makedocs = (pkgs.rustPlatform.buildRustPackage rec {
              pname = "cargo-makedocs";
              version = "1.2.0";

              src = pkgs.fetchFromGitHub {
                owner = "Bunogi";
                repo = "cargo-makedocs";
                rev = "${version}";
                sha256 = "kTyAnnJIrpfoN/kmnfA+TlA70K7AtzrogqT0YUi5P+I=";
              };

              cargoSha256 = "gHpWWPTrY5lcgaFWGbSZ17IPuEJdPSpbYraapCdO1C8=";

              meta = with pkgs.lib; {
                description = "A cargo subcommand to build documentation for direct dependencies of your current crate.";
                homepage = "https://github.com/Bunogi/cargo-makedocs/tree/1.2.0";
                license = licenses.mit;
                maintainers = with maintainers; [ bootstrap-prime ];
              };
            });
          # unfortunately we cannot use an llvm environment because littlefs requires gcc to build.
          in pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              # get current rust toolchain defaults (this includes clippy and rustfmt)
              rust

              pkg-config
              tpm2-tss
              openssl

              # required for rust docs in org-mode
              pandoc
              fd
              cargo-makedocs

              # for a good developer experience
              cargo-edit
            ];

            CARGO_NET_GIT_FETCH_WITH_CLI = "true";
            RUST_BACKTRACE = 1;
          };

          defaultPackage = crane.lib.${system}.buildPackage {
            src = ./.;

            buildInputs = with pkgs; [ tpm2-tss openssl ];
            nativeBuildInputs = with pkgs; [ pkg-config ];
            doCheck = true;
          };

          checks = {
            build = self.defaultPackage.${system};

            format = pkgs.runCommand "check-format" { buildInputs = [ rust ]; } ''
              ${rust}/bin/cargo-fmt fmt --manifest-path ${./.}/Cargo.toml --check
              touch $out
            '';

            typos = pkgs.runCommand "typos" { buildInputs = [ pkgs.typos ]; } ''
              ${pkgs.typos}/bin/typos -- ${./.}
              touch $out
            '';
          };
        }
    );
}
