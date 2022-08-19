{
  description = "Build L[ightning PayJ]oin and its Development Environment";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    nix-bitcoin.url = "github:fort-nix/nix-bitcoin/release";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, utils, naersk, nix-bitcoin, nixpkgs }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
        };

        naersk' = pkgs.callPackage naersk {};
        version = builtins.substring 0 8 self.lastModifiedDate;
      in {
        packages = {
          # For `nix build` & `nix run`:
          default = naersk'.buildPackage {
            pname = "loin";
            inherit version;

            src = ./.;
          };

          # For `nix develop`:
          devShells.default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ rustc cargo  ] ++ (
                lib.optional stdenv.isDarwin [
                  libiconv
                  # For `tonic_lnd`
                  darwin.apple_sdk.frameworks.Security pkgconfig openssl
                ]
              );
          };

          # nixosModules.default = { config, pkgs, ... }: {
          #   imports = [ nix-bitcoin.nixosModules ];

          #   options = {
          #     nix-bitcoin.userVersionLockedPkgs = mkOption {
          #       type = types.bool;
          #       default = false;
          #       description = ''
          #         Use the nixpkgs version locked by this flake for `nix-bitcoin.pkgs`.
          #         Only relevant if you are using a nixpkgs version for evaluating your system
          #         that differs from the one that is locked by this flake (via input `nixpkgs`).
          #         If this is the case, enabling this option may result in a more stable system
          #         because the nix-bitcoin services use the exact pkgs versions that are tested
          #         by nix-bitcoin.
          #         The downsides are increased evaluation times and increased system
          #         closure size.
          #         If `false`, the default system pkgs are used.
          #       ''
          #     }
          #   }
          # }
          bitcoin = {
              nixosConfigurations.mynode = nix-bitcoin.inputs.nixpkgs.lib.nixosSystem {
                system = "x86_64-linux";
                modules = [
                  nix-bitcoin.nixosModules.default

                  # Optional:
                  # Import the secure-node preset, an opinionated config to enhance security
                  # and privacy.
                  #
                  # "${nix-bitcoin}/modules/presets/secure-node.nix"

                  {
                    # Automatically generate all secrets required by services.
                    # The secrets are stored in /etc/nix-bitcoin-secrets
                    nix-bitcoin.generateSecrets = true;

                    # Enable services.
                    # See ../configuration.nix for all available features.
                    services.bitcoind.enable = true;
                    services.bitcoind.regtest = true;

                    # When using nix-bitcoin as part of a larger NixOS configuration, set the following to enable
                    # interactive access to nix-bitcoin features (like bitcoin-cli) for your system's main user
                    nix-bitcoin.operator = {
                      enable = true;
                      name = "main"; # Set this to your system's main user
                    };

                    # The system's main unprivileged user. This setting is usually part of your
                    # existing NixOS configuration.
                    users.users.main = {
                      isNormalUser = true;
                      password = "a";
                    };

                    # If you use a custom nixpkgs version for evaluating your system
                    # (instead of `nix-bitcoin.inputs.nixpkgs` like in this example),
                    # consider setting `useVersionLockedPkgs = true` to use the exact pkgs
                    # versions for nix-bitcoin services that are tested by nix-bitcoin.
                    # The downsides are increased evaluation times and increased system
                    # closure size.
                    #
                    # nix-bitcoin.useVersionLockedPkgs = true;
                  }
                ];
              };
          };

          docker = let
            loin = self.packages.${system}.default;
            bitcoin = self.packages.${system}.bitcoin;
          in pkgs.dockerTools.buildLayeredImage {
            name = "loin-integration";
            contents = [ loin ];

            config = {
              WorkingDir = "/";
            };
          };
        };
      }
    );
}
