{
  description = "Build L[ightning PayJ]oin and its Development Environment";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, utils, naersk, nixpkgs }:
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
            nativeBuildInputs = with pkgs; [ rustc cargo ] ++ (
                lib.optional stdenv.isDarwin [
                  libiconv
                  # For `tonic_lnd`
                  darwin.apple_sdk.frameworks.Security pkgconfig openssl
                ]
              );
          };

          docker = let
            loin = self.packages.${system}.default;
          in pkgs.dockerTools.buildLayeredImage {
            name = "loin-integration";
            tag = loin.version;
            contents = [ loin ];

            config = {
              Cmd = ["echo 'hi from docker'"];
              WorkingDir = "/";
            };
          };
        };
      }
    );
}
