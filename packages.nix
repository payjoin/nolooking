let
# Pinning to revision e0361a947ed3eb692e43786f78e86075395ef3af for cln v0.11.1 
# and lnd v0.15.0-beta.
rev = "e0361a947ed3eb692e43786f78e86075395ef3af";
nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
pkgs = import nixpkgs {};

# Override priority for bitcoin as /bin/bitcoin_test will
# confilict with /bin/bitcoin_test from elementsd.
bitcoin = (pkgs.bitcoin.overrideAttrs (attrs: {
    meta = attrs.meta or {} // {
        priority = 0;
    };
}));

in with pkgs;
{
    execs = {
        bitcoin = bitcoin;
        lnd = lnd;
        mermaid = nodePackages.mermaid-cli;
    };
    testpkgs = [ rustc cargo bitcoin lnd];
    devpkgs = [ bitcoin lnd docker-compose jq nodePackages.mermaid-cli ];
}
