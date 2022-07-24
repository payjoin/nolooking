# Lightning Optimizing Opening Server

(loptoš ~ naughty boy/brat/hooligan/..., not to be confused with lopta == ball)

## WARNING: ULTRA-EXPERIMENTAL SOFTWARE!!!

**This project is very early and lacks basic checks (that means it's NOT fully BIP78-compliant)!
For the love of god, do NOT use it on mainnet just yet!
If you don't want to wait long, help with reviews and PRs.**

## About

This server optimizes your channel opening from a remote wallet which supports PayJoin.
It enables you to open one or more channels from a remote LND with an empty wallet using sats in PayJoin-compliant wallet.
This way you save one chain transaction when opening from Wasabi (untested), Blue Wallet (untested), BTCPayServer (tested, works), or other PayJoin-supporting wallet.
It's basically a user-friendly way to do PSBT funding flow.

And yes, in the future you could give the URI/QR code to someone else, so you receive a PayJoin transaction and simultaneously open Lightning channel with the received money.

### Expected fee savings

The classic scenario of sending to LND wallet and then opening a channel involves two transactions.
With PayJoin it involves just one transaction, saving 106 vB (68 vB input + 22 vB script pubkey + 8 vB output amount + 4 vB version + 4vB timelock)
Sending to a node and then opening 10 channels can turn 11 transactions into one, saving 1060 vB.
Same if someone else pays you and you already decided to use the received money to open channel(s).
You will also save shitton of time not having to wait for confirmations.
(There's `--spend-unconfirmed`, but maybe not a good idea for long chains?)

### Expected privacy implications

If you open a channel with a ususal LN wallet, it's pretty much certain that the change belongs to the funder.
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

- **MOST LIKELY UNSAFE** does not implement required BIP78 checks
- **Only works with a LND 0.14** - do **not** attempt to bypass the check - guaranteed loss of funds!
- To work with an _empty_ LND wallet you need to use LND 0.14.2
- Funds in LND or other wallet are not used, so it's not true PayJoin, just abuses the protocol to coordinate PSBT.
- Unpolished UI
- No way to inteligently manipulate the amount
- No discount possible
- Invalid request can kill whole server
- `.unwraps()`s EVERYWHERE!
- I swear I knew about a few more but can't remember right now :D

## Usage

0. You need Rust version 1.48 or higher to compile this.
1. Assuming you already have LND 0.14, ideally 0.14.2
2. `cargo build`
3. Setup reverse HTTP proxy with HTTPS forwarding to some port - e.g. 3000.
   You can do this in a few lines using [selfhost in Cryptoanarchy Debian Repository](https://github.com/debian-cryptoanarchy/cryptoanarchy-deb-repo-builder/blob/master/docs/user-level.md#selfhost).
4. `./target/debug/loptos HTTP_BIND_PORT https://LND_GRPC_ADDRESS /path/to/cert/file /path/to/admin.macaroon FEE_RATE_SAT_PER_VB DEST_NODE_URI AMOUNS_IN_SATS [DEST_NODE_URI AMOUNS_IN_SATS ...] [CHAIN_WALLET_AMOUNT_SATS]`
5. Copy BIP21 from command line output and paste it into one of the supported wallets
6. Confirm the transaction and pray it works

## Dev set up

0. Copy `conf_dir/conf.template` to `conf_dir/conf` and replace values
1. `cargo run`

Note: if `CHAIN_WALLET_AMOUNT_SATS` is present another output will be added to send the amount to the internal wallet.
This may be required in case the wallet is empty as in such case LND can not reserve sats for anchor commitments.
However, to truly work, you need LND 0.14.2.

## License

The license is MIT, with one restriction and one warning:

You are forbidden from preventing people from distributing, analyzing or modifying your source code or binaries they unless they specifically signed a contract with you in which they committed to not do so.

**I will be maximally helpful towards your victims suing you if you ever market, vendor or distribute this software in exchange for payment or free of charge in a way that could make it look like a reliable or tested product unless you demonstrate serious work done reviewing and improving the code before doing so. Such must be done by people with good knowledge of Rust, cryptography, Bitcoin, network protocols and security.**
