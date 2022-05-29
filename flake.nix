{
  description = "Nix flake to pin everything in place for the rust dev env.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs@{ self, flake-utils, nixpkgs, rust-overlay, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
        rec {
          devShell = let
            rust = (pkgs.rust-bin.selectLatestNightlyWith (toolchain:
              toolchain.default.override {
                extensions = [ "rust-src" "rustfmt" "rust-analyzer-preview" ];
              }));
          # unfortunately we cannot use an llvm environment because littlefs requires gcc to build.
          in pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              # get current rust toolchain defaults (this includes clippy and rustfmt)
              rust

              pkg-config
              tpm2-tss

              # for a good developer experience
              cargo-edit
            ];

            CARGO_NET_GIT_FETCH_WITH_CLI = "true";
            RUST_BACKTRACE = 1;
          };

          defaultPackage = crane.lib.${system}.buildPackage {
            src = ./.;

            buildInputs = [ pkgs.tpm2-tss ];
            nativeBuildInputs = [ pkgs.pkg-config ];
            doCheck = true;
          };
        }
    );
}
