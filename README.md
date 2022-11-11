<img align="left" style="height: 6em; width: 6em;" src="https://user-images.githubusercontent.com/8525467/201369193-f3e00fe8-e1a7-4524-b120-b7ab21ef4a57.svg">

# nolooking: Open All Your Channels in 1 Transaction

&nbsp;

Funding channels the old way is a pain. First you'd fund your node on-chain, wait around, then open channels 1 by 1. Instead, nolooking funds and opens channels after you scan just 1 QR code.

A new node can get connected in one transaction that opens inbound *and* outbound channels using pay-to-endpoint. Privacy is just a bonus.

Nolooking leverages Pay-to-Endpoint ([BIP78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) PayJoin) to negotiate a channel open for your lightning node from any BIP78 [supporting wallet](https://en.bitcoin.it/wiki/PayJoin_adoption). Previously, custom PSBT channel funding could only be done by [signing PSBTs manually](https://github.com/lightningnetwork/lnd/blob/master/docs/psbt.md). A node running nolooking can open many new lightning channel with every inbound transaction, provided the payer supports BIP78. E.g. by using Sparrow wallet, BTCPayServer, or Wasabi; following the normal QR scan and payjoin payment flow. Read the article about [Lightning Powered PayJoin](https://chaincase.app/words/lightning-payjoin?ref=github) to hear how it can save your privacy, time, and money!

## ⚠️ WARNING: ULTRA-EXPERIMENTAL SOFTWARE

❗️ **This project is pre-alpha quality and lacks basic checks. It is NOT fully BIP78-compliant** ❗️

Any unexpecected node version will likely cause permanent loss of funds.

## Usage

Requires:
* Rust version 1.48 or higher to compile
* LND v14.2 or higher

* **Only works with a LND 0.14** - do **not** attempt to bypass the check - guaranteed loss of funds!


Install:
1. Build and install the binary with
```
cargo install --path .
```
2. Setup a reverse HTTP proxy with HTTPS forwarding to some port - e.g. 3000.
   You can do this in a few lines using [local-ssl-proxy](https://www.storyblok.com/faq/setup-dev-server-https-proxy). Or use NGINX.
3. Create a configuration file `nolooking.conf` containing:
```
bind_port=3000
endpoint="https://localhost:3010"
lnd_address="https://localhost:10009"
lnd_cert_path="/home/dan/.lnd/tls.cert"
lnd_macaroon_path="/home/dan/.lnd/data/chain/bitcoin/mainnet/admin.macaroon"
```
   - Lines starting with `lnd_` specify your connection to your bitcoin node.

   - You will be able to view the nolooking site on `bind_port` and the payjoin endpoint will be `endpoint` (e.g. can be a domain).

4. Run with `nolooking --conf nolooking.conf`
5. Visit Nolooking on [127.0.0.1](http://127.0.0.1:3000) and queue some bitcoin channels.
6. Generate the QR code, pay it or share it! Once a payjoin transaction has enough confirmations, your new lightning channels will be established and you can move your sats over the lightning nework!


## Expected fee savings

In the traditional path for opening a lightning channel, you first must fund the LND wallet and then make a second transaction to fund the opening of the channel, a total of two transactions.
Nolooking however does this all in a single transaction, saving **106 vB** (68 vB input + 22 vB script pubkey + 8 vB output amount + 4 vB version + 4vB timelock).

If you wanted to fund a number of channels, say 10 channels, this would traditionally take 11 transactions. Nolooking can do this in a single transaction - saving 1060 vB.

You can also schedule channel opens, such that when someone goes to pay you lightning channel funding transactions piggyback along with their payment. Again not only saving fees and also saving you a shedload of time since you don't have to wait for confirmations in between each successive channel open.
(There's `--spend-unconfirmed`, but that has its own drawbacks)

## Expected privacy implications

If you open a lightning channel the usual way, common input heuristic makes a good assumption that the change from this funding transaction belongs to the funder.
The payjoin provided by nolooking breaks that assumption, where this change could now be the payer's change instead.

Just as with any other PayJoin, it becomes unclear whether all inputs of a transaction belong to a single funder or whether there are indeed multiple parties funding the transaction.

Because this tool breaks analytic assumptions regarding bitcoin transactions in general, using it will add transactions to the network which have a large set of possible interpretations and thus better privacy.

## Future research
Sadly, I don't think the payjoin sender can can also safely open a lightning channel using change from the transaction, but I have some ideas how it could be achieved in the future.

If lightning channels were truly private, then this tool could make chain analytics even more confusing since heurestics may incorrectly assume a transaction funds a single node instead of two or even several.

With Post-Taproot-LN it will be impossible to distinguish a CoinJoin from a batch open of several same-sized private channels. Actually, CoinJoin and batch opening of several same-sized private channels could be one transaction. Good luck analyzing that!

## UX implications

All of this is possible without nolooking by [manually exchanging PSBTs](https://github.com/lightningnetwork/lnd/blob/master/docs/psbt.md).
BIP78 turns that tedious back and forth into scanning/clicking one link, followed by confirmation in the wallet.
In other words, your grandmother will be able to somewhat privately open a bunch of channels for you, using her BIP78-capable wallet on her iPad.

## Limitations and future plans

* **UNSAFE** -- does not implement required BIP78 checks
* **Only works with a LND 0.14** - do **not** attempt to bypass the check - guaranteed loss of funds!
* To work with an *empty* LND wallet you need to use LND 0.14.2
* Funds in LND or other wallet are not used, so it's not true PayJoin.
* Invalid request can kill the whole server

## License

The license is MIT, with one restriction and one warning:

You are forbidden from preventing people from distributing, analyzing or modifying your source code or binaries they unless they specifically signed a contract with you in which they committed to not do so.

**I will be maximally helpful towards your victims suing you if you ever market, vendor or distribute this software in exchange for payment or free of charge in a way that could make it look like a reliable or tested product unless you demonstrate serious work done reviewing and improving the code before doing so. Such must be done by people with good knowledge of Rust, cryptography, Bitcoin, network protocols and security.**
