#!/bin/bash
set -ex

if [ $# -eq 0 ]
  then
    echo "No arguments supplied. Expecting node name"
fi


# testnet or mainnet
network=regtest
echo "[DEBUG] lnd-init.sh: Starting to provision lnd"
echo "[DEBUG] lnd-init.sh: Network: ${network}"

# default paths
seed_location=/data/seed.txt
walletpassword_location=/data/walletpassword.txt
tls_cert_location=/data/tls.cert
channel_back_up_location=/data/data/chain/bitcoin/testnet/channel.backup

if [[ ! -f $seed_location ]]; then
    lndinit gen-seed > $seed_location
fi

if [[ ! -f $walletpassword_location ]]; then
    lndinit gen-password > $walletpassword_location
fi

# Create the wallet database with the given seed and password files. If the wallet already exists, we make sure we can actually unlock it with the given password file. This will take a few seconds in any case.
lndinit -v init-wallet \
    --secret-source=file \
    --file.seed=$seed_location \
    --file.wallet-password=$walletpassword_location \
    --init-file.output-wallet-dir=/data/chain/bitcoin/$network \
    --init-file.validate-password
echo "[DEBUG] lnd Wallet initialized"

# Start lnd
lnd --configfile=/data/lnd.conf \
    --wallet-unlock-password-file=$walletpassword_location &
echo "[DEBUG] lnd Started"

# Wait for lnd to server to start 
lnd_status="$(lncli --network regtest state | jq -r .state)"
# Wait till lnd starts
while [ $lnd_status != "SERVER_ACTIVE" ]
do
  lnd_status="$(lncli --network regtest state | jq .state)"
  echo "[DEBUG] Waiting for lnd to start. Server status $lnd_status"
  sleep 5
done
while [ 1 -ne 0 ]
do
  # Do busy work / alerting / monitoring here
  sleep 1
done