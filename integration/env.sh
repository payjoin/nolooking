#!/usr/bin/env bash

# ENVs: paths
ROOT="$(pwd)/integration"
ROOT_STATIC="${ROOT}/static"
ROOT_TEMP="${ROOT}/temp"
ROOT_BIN="${ROOT}/temp/bin"

function clear_temp() {
    rm -rf "${ROOT_TEMP}"
}

# ensure paths exists
function ensure_paths() {
    mkdir -p ${ROOT_TEMP}
    mkdir -p ${ROOT_BIN}
}

# ENVs: 

## Steps:
## * Run bitcoind in regtest
## * Run lnd funder
## * Run lnd fundee

function install_lnd_v0_15_0() {
    # TODO: Support different OS and target with `uname`
    wget -nv -P "${ROOT_BIN}" "https://github.com/lightningnetwork/lnd/releases/download/v0.15.0-beta/lnd-linux-amd64-v0.15.0-beta.tar.gz"
    # Unzip
    tar -xvzf "${ROOT_BIN}/lnd-linux-amd64-v0.15.0-beta.tar.gz" -C "${ROOT_BIN}"
    # Move
    mv $ROOT_BIN/lnd-linux-amd64-v0.15.0-beta/* $ROOT_BIN
    # Remove folders and archive
    rm -rf $ROOT_BIN/lnd-linux-amd64-v0.15.0-beta*
}

function install_bitcoind() {
    # TODO: Support different OS and targets with `uname`
    wget -nv -P "${ROOT_BIN}" "https://bitcoincore.org/bin/bitcoin-core-23.0/bitcoin-23.0-x86_64-linux-gnu.tar.gz"
    # Unzip
    tar -xvzf "${ROOT_BIN}/bitcoin-23.0-x86_64-linux-gnu.tar.gz" -C "${ROOT_BIN}"
    # Move
    mv $ROOT_BIN/bitcoin-23.0/bin/* $ROOT_BIN
    # Remove folders and archive
    rm -rf $ROOT_BIN/bitcoin-23.0*
}

function start_bitcoind() {
    if [[ $# -ne 2 ]]; then
        echo "expected 2 arg(s), got $#" 1>&2
        exit 1
    fi

    data_dir=$0
    rpc_port=$1

    ${ROOT_BIN}/bitcoind -regtest -datadir=$data_dir \
        -server -rpcuser=bitcoin -rpcpassword=bitcoin -rpcbind=127.0.0.1::$rpc_port \


}

echo "${ROOT}"

# clear_temp
# ensure_paths
# install_lnd_v0_15_0
# install_bitcoind
start_bitcoind
