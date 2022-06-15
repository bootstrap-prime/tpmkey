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

          checks = let
            makeTest = (import (nixpkgs + "/nixos/lib/testing-python.nix") {
              inherit system;
              extraConfigurations = [{
                # TODO: add a systemd module to start up the vtpm
                # this extraConfigurations gets run in each individual vm
              }];
            }).makeTest;

            # tpm options to enable qemu utilizing the swtpm started up by the test script
            tpm_opts = {
              virtualisation.qemu.options = [
                "-chardev socket,id=chrtpm,path=/tmp/swtpm-sock"
                "-tpmdev emulator,id=tpm0,chardev=chrtpm"
                "-device tpm-tis,tpmdev=tpm0"
              ];

              environment.sessionVariables.TPM2TOOLS_TCTI = "device:/dev/tpmrm0";
            };
            # test script that starts up the swtpm
            tpm_script = ''
              import subprocess
              import tempfile

              def start_swtpm(tpmstate):
                subprocess.Popen(["${pkgs.swtpm}/bin/swtpm", "socket", "--tpmstate", "dir="+tpmstate, "--ctrl", "type=unixio,path=/tmp/swtpm-sock", "--log", "level=0", "--tpm2"])

              with tempfile.TemporaryDirectory() as tpmstate:
                start_swtpm(tpmstate)
            '';

          in rec {
            build = self.defaultPackage.${system};

            # add additional tests for each key type:
            # - key generation test, ensure ssh can recognize the key as a key
            # - ensure you can log in to a remote with this key
            # these tests can be made with makeTest
            # these can be made with https://edolstra.github.io/pubs/decvms-issre2010-final.pdf keywords `makeTest nixos`
            # https://github.com/NixOS/nixpkgs/blob/e6123938cafa5f5a368090c68d9012adb980da5f/nixos/lib/testing-python.nix#L149
            # https://github.com/edolstra/dwarffs/blob/e768ce3239156de05f7ff3210d86a80762730f30/flake.nix#L54

            login-rsa = makeTest {
              name = "login-rsa";
              nodes = {
                client = { ... }: {
                  users.extraUsers.bob = {
                    home = "/home/bob";
                    isNormalUser = true;
                  };

                  systemd.user.services.sekey-agent = {
                    wantedBy = [ "default.target" ];
                    serviceConfig = {
                      ExecStart = "${build}/bin/sekey --daemon";
                      Type = "exec";
                    };
                  };

                  environment.sessionVariables.SSH_AUTH_SOCK = "/root/.tpmkey/ssh-agent.ssh";
                  services.openssh.enable = true;
                } // tpm_opts;
              };

              testScript = ''
                  ${tpm_script}
                    start_all()
                    client.wait_for_unit("multi-user.target")

                    client.succeed("${build}/bin/sekey --generate-keypair 'test'")
                    client.succeed("${build}/bin/sekey --export-key 'test' > ./pub.key")
                    client.succeed("mkdir -p /home/bob/.ssh && touch /home/bob/.ssh/authorized_keys")
                    client.succeed("cat ./pub.key >> /home/bob/.ssh/authorized_keys")
                    client.start_job("sekey-agent.service", "root")
                    client.succeed("${pkgs.openssh}/bin/ssh bob@localhost '''exit $([[ $USER == 'root\n' ]])''' ")
              '';
            };

            generate-key = makeTest {
              name = "ensure-valid-key";
              nodes = {
                client = { ... }: {
                } // tpm_opts;
              };

              testScript = ''
                  ${tpm_script}
                    start_all()
                    client.wait_for_unit("multi-user.target")

                    client.succeed("${build}/bin/sekey --generate-keypair 'test'")
                    client.succeed("${build}/bin/sekey --export-key 'test' > ./pub.key")
                    client.succeed("${pkgs.openssh}/bin/ssh-keygen -l -f ./pub.key")
              '';
            };

            # TODO: rewrite RustCrypto/formats/ssh-key to support serializing and deserializing out of the openssh wrapper
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
