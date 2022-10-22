# L[ightningPayJ]oin: Automated External Lightning Channel Funding

This server leverages Pay-to-Endpoint to negotiate channel funding on your lightning node from an external wallet supporting BIP78. Previously, external funding could only be done by [signing PSBTs manually](https://github.com/lightningnetwork/lnd/blob/master/docs/psbt.md). A node running this software can open a new scheduled lightning channel upon payment receipt from e.g. BTCPayServer with a normal QR scan transfer flow.

## ⚠️ WARNING: ULTRA-EXPERIMENTAL SOFTWARE

❗️ **This project is pre-alpha quality and lacks basic checks. It is NOT fully BIP78-compliant** ❗️

Any unexpecected node setup or message will likely cause permanent loss of funds.

For the love of god, do NOT use it on mainnet just yet!
If you don't want to wait long, help with reviews and PRs

## Benefits

Read the article about [Lightning Powered PayJoin](https://chaincase.app/words/lightning-payjoin?ref=github).

### Expected fee savings

The classic scenario of sending to LND wallet and then opening a channel involves two transactions.
With this software's PayJoin it involves just one transaction, saving 106 vB (68 vB input + 22 vB script pubkey + 8 vB output amount + 4 vB version + 4vB timelock).
Sending to a node and then opening 10 channels can turn 11 transactions into one, saving 1060 vB.
If someone were to pay you and you already scheduled to open channel openings, you would save too.
You will also save a shedload of time you would otherwise spend waiting for confirmations.
(There's `--spend-unconfirmed`, but that has its own drawbacks)

### Expected privacy implications

If you open a channel with a usual LN wallet, common input heuristic makes a good assumption that the change belongs to the funder.
This tool breaks that assumption. It could now be a payer's change.
This tool may produce many changes. Because it breaks analytic assumptions regarding bitcoin transactions in general, many transactions on the network have a larger set of possible interpretations.

Just as with any other PayJoin, it's unclear whether all inputs belong to the funder or some of them don't.

Sadly, I don't think the payer can safely open a channel from change(s) but I have some ideas how it could be achieved in the future.
If the channels were truly private it'd make analysis even more confusing (incorrectly assume it's one node).

Post-Taproot-LN it will be impossible to distinguish CoinJoin from batch open of several same-sized private channels.
Actually, CoinJoin and batch opening of several same-sized private channels could be one transaction.
Good luck analyzing that!

### UX implications

All this is possible without loin by [manually exchanging PSBTs](https://github.com/lightningnetwork/lnd/blob/master/docs/psbt.md).
BIP78 turns that tedious back and forth into scanning/clicking one link followed by confirmation in the wallet.
In other words, your grandmother will be able to somewhat privately open a bunch of channels for you, if she has a BIP78-capable wallet.

## Limitations and future plans

* **MOST LIKELY UNSAFE** does not implement required BIP78 checks
* **Only works with a LND 0.14** - do **not** attempt to bypass the check - guaranteed loss of funds!
* To work with an *empty* LND wallet you need to use LND 0.14.2
* Funds in LND or other wallet are not used, so it's not true PayJoin, just abuses the protocol to coordinate PSBT.
* Unpolished UI
* No way to inteligently manipulate the amount
* No discount possible
* Invalid request can kill whole server
* `.unwraps()`s EVERYWHERE!
* I swear I knew about a few more but can't remember right now :D

## Usage

0. You need Rust version 1.48 or higher to compile this.
1. You need LND v14.2 or higher
2. `cargo build [--features=test_paths]`. The test_paths feature will serve the `static/index.html` ui contained in this folder rather than one in `/usr/share/loin/static` in production.
3. Setup reverse HTTP proxy with HTTPS forwarding to some port - e.g. 3000.
   You can do this in a few lines using [selfhost in Cryptoanarchy Debian Repository](https://github.com/debian-cryptoanarchy/cryptoanarchy-deb-repo-builder/blob/master/docs/user-level.md#selfhost). or [on MacOS](https://www.storyblok.com/faq/setup-dev-server-https-proxy)
4. create a configuration file based on `config_spec.toml`. This is mine based on a [polar](https://lightningpolar.com/) lightning network simulator setup. `CONFIGURATION_FILE=loin.conf`:

   ```configuration
   # loin.conf

   bind_port=3000
   endpoint="https://localhost:3010"
   lnd_address="https://localhost:10004"
   lnd_cert_path="/Users/dan/.polar/networks/1/volumes/lnd/dave/tls.cert"
   lnd_macaroon_path="/Users/dan/.polar/networks/1/volumes/lnd/dave/data/chain/bitcoin/regtest/admin.macaroon"
   ```

5. `cargo run --features=test_paths -- --conf CONFIGURATION_FILE_PATH FEE_RATE DEST_NODE_URI AMOUNT_IN_SATS [DEST_NODE_URI AMOUNT_IN_SATS ...] [CHAIN_WALLET_AMOUNT_SATS]`
6. Copy BIP21 from command line output and paste it into one of the supported wallets. I use [the payjoin crate client](https://github.com/Kixunil/payjoin/tree/master/payjoin-client) to make a payjoin right from regtest bitcoind.
7. Confirm the transaction and move some sats over the new channel


Note: if `CHAIN_WALLET_AMOUNT_SATS` is present a single-sig output will be added to LND's internal wallet.
A minimum internal wallet balance of 10,000 reserve sats per channel up to 100,000 sats is required for anchor commitments. This [can be automated](https://github.com/Kixunil/loin/issues/11) in the future.

## License

The license is MIT, with one restriction and one warning:

You are forbidden from preventing people from distributing, analyzing or modifying your source code or binaries they unless they specifically signed a contract with you in which they committed to not do so.

**I will be maximally helpful towards your victims suing you if you ever market, vendor or distribute this software in exchange for payment or free of charge in a way that could make it look like a reliable or tested product unless you demonstrate serious work done reviewing and improving the code before doing so. Such must be done by people with good knowledge of Rust, cryptography, Bitcoin, network protocols and security.**
