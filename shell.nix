let
    loin-pkgs = import ./packages.nix;
in
{ pkgs ? (import <nixpkgs> {})}:
let
    execs = loin-pkgs.execs;
in with pkgs;
stdenv.mkDerivation rec {
    name = "loin-dev-env";
    nativeBuildInputs = [openssl];
    buildInputs = [ loin-pkgs.devpkgs ];
    
    shellHook = ''
    alias bitcoind='${execs.bitcoin}/bin/bitcoind'
    alias bitcoin-cli='${execs.bitcoin}/bin/bitcoin-cli'
    alias lnd='${execs.lnd}/bin/lnd'
    alias lncli='${execs.lnd}/bin/lncli'

    . ./startup_regtest.sh
    setup_alias
    '';
}

