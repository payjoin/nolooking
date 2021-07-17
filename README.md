# Lightning Optimizing Opening Server

(loptoš ~ naughty boy/brat/hooligan/..., not to be confused with lopta == ball)

## WARNING: ULTRA-EXPERIMENTAL SOFTWARE!!!

**This project is very early and lacks basic checks (that means it's NOT fully BIP78-compliant)!
For the love of god, do NOT use it on mainnet just yet!
If you don't want to wait long, help with reviews and PRs.**

This server optimizes your channel opening from a remote wallet which supports PayJoin.
It enables you to open a channel on remote LND with empty wallet using sats in PayJoin-compliant wallet.
This way you save one chain transaction when opening from Wasabi, BTCPayServer, Blue Wallet or other PayJoin-supporting wallet.
It's basically a user-friendly way to do PSBT funding flow.

And yes, int he future you could give the URI/QR code to someone else, so you receive PayJoin transaction and simultaneously open Lightning channel with received money.

## Limitations and future plans

* **MOST LIKELY UNSAFE** does not implement required BIP78 checks
* **Only works with a [forked LND](https://github.com/guggero/lnd/tree/psbt-no-final-tx)** - there's a PR against LND, should land in 0.14.
* Funds in LND or other wallet are not used, so it's not true PayJoin, just abuses the protocol to coordinate PSBT.
* CLI-only
* No way to inteligently manipulate the amount
* No discount possible
* Invalid request can kill whole server
* `.unwraps()`s EVERYWHERE!
* I swear I knew about a few more but can't remember right now :D

## Usage

0. You need a [recent version of Rust](https://rustup.rs) to compile this.
1. You need to clone the **forked** LND: `git clone -b psbt-no-final-tx https://github.com/guggero/lnd/`
2. `LND_REPO_DIR=path/to/forked/lnd/ cargo build`
3. Build forked LND
4. Deploy forked LND (replacing binary in deployment followed by restart works)
5. Setup reverse HTTP proxy with HTTPS forwarding to some port - e.g. 3000.
   You can do this in a few lines using [selfhost in Cryptoanarchy Debian Repository](https://github.com/debian-cryptoanarchy/cryptoanarchy-deb-repo-builder/blob/master/docs/user-level.md#selfhost).
6. Connect to the peer using `lncli connect ...`
7. `./target/debug/loptos HTTP_BIND_PORT https://LND_GRPC_ADDRESS /path/to/cert/file /path/to/admin.macaroon DEST_NODE_ID AMOUN_IN_SATS`
8. Copy BIP21 from command line output and paste it into one of the supported wallets
9. Confirm the transaction and pray it works

## License

The license is MIT, with one restriction and one warning:

You are forbidden from preventing people from distributing, analyzing or modifying your source code or binaries they unless they specifically signed a contract with you in which they committed to not do so.

**I will be maximally helpful towards your victims suing you if you ever market, vendor or distribute this software in exchange for payment or free of charge in a way that could make it look like a reliable or tested product unless you demonstrate serious work done reviewing and improving the code before doing so. Such must be done by people with good knowledge of Rust, cryptography, Bitcoin, network protocols and security.**
