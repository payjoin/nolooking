# Lightning Optimizing Opening Server

(loptoš ~ naughty boy/brat/hooligan/..., not to be confused with lopta == ball)

## WARNING: ULTRA-EXPERIMENTAL SOFTWARE!!!

**This project is very early and lacks basic checks (that means it's NOT fully BIP78-compliant)!
For the love of god, do NOT use it on mainnet just yet!
If you don't want to wait long, help with reviews and PRs.**

## About

This server optimizes your channel opening from a remote wallet which supports PayJoin.
It enables you to open one or more channels from remote LND with empty wallet using sats in PayJoin-compliant wallet.
This way you save one chain transaction when opening from Wasabi, Blue Wallet, BTCPayServer (currently buggy), or other PayJoin-supporting wallet.
It's basically a user-friendly way to do PSBT funding flow.

And yes, in the future you could give the URI/QR code to someone else, so you receive PayJoin transaction and simultaneously open Lightning channel with received money.

### Expected fee savings

The classic scenario of sending to LND wallet and then opening a channel involves two transactions.
With PayJoin it involves just one transaction, saving 106 vB (68 vB input + 22 vB script pubkey + 8 vB output amount + 4 vB version + 4vB timelock)
Sending to a node and then opening 10 channels can turn 11 transactions into one, saving 1060 vB.
Same if someone else pays you and you already decided to use the received money to open channel(s).
You will also save shitton of time not having to wait for confirmations.
(There's `--spend-unconfirmed`, but maybe not a good idea for long chains?)

### Expected privacy implications

If you open a channel with ususal LN wallet, it's pretty much certain that the change belongs to the funder.
This tool makes it uncertain because it could've been a payer.
This tool may produce two changes - it's still unclear whether both or only one belongs to the funder and it may be hard to find which one.
(But there's a good chance it'll be revealed eventually.)

Just as with any other PayJoin, it's unclear whether all inputs belong to the funder or some of them don't.

Sadly, I don't think the payer can safely open a channel from change(s) but I have some ideas how it could be achieved in the future.
If the channels were truly private it'd make analysis even more confusing (incorrectly assume it's one node).

Post-Taproot-LN it will be impossible to distinguish CoinJoin from batch open of several same-sized private channels.
Actually, CoinJoin and batch opening of several same-sized private channels could be one transaction.
Good luck analyzing that!

### UX implications

All this is possible without loptos by manually exchanging PSBTs.
BIP78 just turns that tedious back and forth into scanning/clicking one link followed by confirmation in the wallet.
In other words, your grandmother will be able to somewhat privately open a bunch of channels for you, if she has a BIP78-capable wallet.

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
3. Build forked LND - connsider merging in fix from [#5539](https://github.com/lightningnetwork/lnd/pull/5539)
4. Deploy forked LND (replacing binary in deployment followed by restart works)
5. Setup reverse HTTP proxy with HTTPS forwarding to some port - e.g. 3000.
   You can do this in a few lines using [selfhost in Cryptoanarchy Debian Repository](https://github.com/debian-cryptoanarchy/cryptoanarchy-deb-repo-builder/blob/master/docs/user-level.md#selfhost).
6. Connect to the peer using `lncli connect ...`
7. `./target/debug/loptos HTTP_BIND_PORT https://LND_GRPC_ADDRESS /path/to/cert/file /path/to/admin.macaroon FEE_RATE_SAT_PER_VB DEST_NODE_ID AMOUNS_IN_SATS [DEST_NODE_ID AMOUNS_IN_SATS ...] [CHAIN_WALLET_AMOUNT_SATS]`
8. Copy BIP21 from command line output and paste it into one of the supported wallets
9. Confirm the transaction and pray it works

Note: if `CHAIN_WALLET_AMOUNT_SATS` is present another output will be added to send the amount to the internal wallet.
This may be required in case the wallet is empty as in such case LND can not reserve sats for anchor commitments.
However, to truly work, you need [another LND fix](https://github.com/lightningnetwork/lnd/pull/5539) (merge with the other branch).

## License

The license is MIT, with one restriction and one warning:

You are forbidden from preventing people from distributing, analyzing or modifying your source code or binaries they unless they specifically signed a contract with you in which they committed to not do so.

**I will be maximally helpful towards your victims suing you if you ever market, vendor or distribute this software in exchange for payment or free of charge in a way that could make it look like a reliable or tested product unless you demonstrate serious work done reviewing and improving the code before doing so. Such must be done by people with good knowledge of Rust, cryptography, Bitcoin, network protocols and security.**
