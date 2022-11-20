# Getting Inbound Liquidity Progamatically
## What is Inbound Capacity Refresher
Recieving and sending on the Lightning network depends on your channels and their capacities. The capacity of your channels not only defines the balance held by each party but also limits the amount that can go through the channel. When a channel is opened, the party opening the channel typically defines its overall capacity and initially contributes this capacity as their own capital to the channel. However, the other party may communicate limits, such as a minimum channel size, before the channel is opened.

The amount that send is bound by your local balance.To Aquire outbound capcity a node simply needs some Bitcoin and a Node willing to accept inbound capacity. The ideal peer will be well connected, has perfect uptime, decent 
reputation for routing, and decent [BOS score](https://fulmo.org/bos-score.html). Services facilitating Lightning Netwrork bootstrapping such as a LSP can ping services such as mempool or TODO to get a nodes that willing connect. 

The amount that you can recieve is bound by your channel partners balance. Additionally, not all inbound capacity is the same. For incoming payments, routing nodes need to have enough inbound capacity with their peers. So even if you have solved your inbound capacity problem your peers might not have. TODO what LSP need to do 

## Inbound Liquidity Providers and their pitfalls

Alex Bosworth has a [up-to-date list of inbound liquidity providers](https://docs.lightning.engineering/the-lightning-network/liquidity/how-to-get-inbound-capacity-on-the-lightning-network). Any of the solutions below work well for an individual node operatorl; how well do they work a lightning services? Let's find out: 

### Zero Fee Routing
Zero Fee Routing (ZFR) has one the of largest and best connected nodes on the network managing > 10 BTC. When we first heard about their services, we thought "this is going to be short work". A week after started to code, we saw this tweet.

TODO get TWEET

### Deezy.io

[Deezy](https://deezy.io) provides an atomic swap service. Meaning you already need to have a channel open with them for them to for 

### Voltage Flow

[Voltage Flow]()

### Blocktank

[Blocktank](https://blocktank.to/) has a similar offering to zero fee routing. They quote a channel and present an on-chain address. However, their API geoblocks requests coming from the US. The only ip's we found that were not blocked were ones coming from Australia. We could have set up a proxy service in Australia, however that could be costly.

### Ln2me

### Thor + Bitrefill

### LnBig

### Yalls

[Y'alls](https://yalls.org/about) is a service developed by Alex Bosworth. The inbound channel service requires payment to a ln invoice vs on-chain payment. This provides a barrier to entry for users looking to get bootstraped in the lightning network who dont have outbound capacity yet. Also we want users to get inbound and outbound capacity all in one on-chain transaction.  


## Nolooking Solution

[Nolooking](https://nolooking.chaincase.app/) serves to open multiple outbound channels and a leased inbound channel all in one [P2EP](https://blog.blockstream.com/en-improving-privacy-using-pay-to-endpoint/) transaction. Nolooking users are presented with option to lease inbound capacity. After a transaction is sent to a on-chain deposit address confirmation a Nolooking node operator is notified and opens a outbound channel with the specified capacity. This was

## The Path Forward
Further optimizations can and should be made. BTCPay Server can automate the notifcation mechanism. Once a tranasction is broadcasted BTCPay will notify the Nolooking server. Using the admin.macaroon, Nolooking can open a channel. However, managing liquidity and channels can be a headache. Going forward we look to offload inbound liquidity managment to services such as ln2me or Voltage's flow.   