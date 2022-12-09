# Tests

## Integration Tests

The integration test script should succeed as long as docker is running.

## Regtest Polar Test Environment

[Polar](https://lightningpolar.com/) makes it simple to spin up and down every type of lightning node imaginable. Install it and build the following network to try nolooking.

1. Make sure [docker](https://www.docker.com/) is installed and started
2. Configure a new network with exactly 2 supported LND nodes and 1 bitcoind node
3. Start it up
4. Mine 100 bocks. You can specify 100 when you click on the bitcoind node in the Actions tab
5. make a `regtest.conf` based on your the first node in your network. network index and node name may change

```conf
# regtest.conf

bind_port=3000
endpoint="https://localhost:3010"
lnd_address="https://localhost:10001"
lnd_cert_path="/Users/dan/.polar/networks/0/volumes/lnd/alice/tls.cert"
lnd_macaroon_path="/Users/dan/.polar/networks/0/volumes/lnd/alice/data/chain/bitcoin/regtest/admin.macaroon"
```

6. start up nolooking `nolooking --conf regtest.conf`
7. visit nolooking in your browser
8. copy the P2P internall address for the second node in your polar network.
9. paste it into nolooking to complete the form and get a bip21
10. pay the payjoin bip21 uri from a client configure to use polar bitcoind, perhaps JoinMarket or [payjoin-client](https://github.com/DanGould/rust-payjoin/tree/master/payjoin-client)