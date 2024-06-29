
# CatCoin

CatCoin is a little personal cryptocurrency project, written from scratch for educational purpose. It covers simple transactions and proof of work nodes.

*by Avo-Catto*

# Why did I make it? 

I only wrote this cryptocurrency for the sake of education and because I needed a more challenging project. 

**From this project I've learned:**

- how cryptocurrencies work in general
- Rust
- Multi Threading & Mutli Processing
- Distributed Programming

# How to use it

**This is a guide about how to run and use this project. By following the steps, you'll learn everything you need to know.**

> **TIP:** Set up the client first before the node.

> **NOTE:** I have to admit that I developed this project on Arch Linux and didn't test it on windows :)

## Client

1. Make sure you've installed git and Rust. The basic stuff of it should be enough I think.
2. Clone the repository: 

        git clone https://github.com/Avo-Catto/CatCoin.git

3. Execute the client:

        cargo run --bin client --release

    After you executed the client, you'll see some error messages, 
    because the client couldn't connect to any node, 
    but that's fine, because we don't have any running so far.

    > **TIP:** If you type `help` you'll get an overview of all of the available commands.

4. Let's create a new user by typing `new user`:

        [~]> new user
        [~]> username: avo
        [~]> password:
        [+]  created new user: avo

5. Before we can create a wallet, you have to log in by typing `login`:

        [~]> login
        [~]> username: avo
        [~]> password:

        [+]>------------------------------<[+]
         V                                  V
         |           Welcome avo!           |
         A                                  A
        [+]>------------------------------<[+]

5. Now we create a wallet by typing `new wallet`:

        [~]> new wallet
        [+]  creating new wallet proceed
        [+]  write some mnemonics:
        [~]> avocado's aren't that delicious as you might think

6. The last thing we need is an address which you can mine on. So simply type `new address`:

        [~]> new address
        [+]  IDX: 0 > 494A4mrmVgJUMDZJRbgbwALWQPUuu5cKM8m8DceovGDmLFR

## Node

> **TIP:** You can run the node with the `--help` flag to get an overview of the other arguments.
>   
>       Usage: node [OPTIONS]
>
>       Options:
>           -i, --ip <IP>
>               address of node [default: 127.0.0.1]
>           -p, --port <PORT>
>               port of node [default: 8000]
>           -g, --genisis
>               create genisis block
>           -n, --node <NODE>
>               entry from node to join the network [default: 127.0.0.1:8000]
>           -e, --expected <EXPECTED>
>               expected time to mine a block 2m:3h:5d:2w - valid after 2 minutes, 3 hours, 5 days, 2 weeks [default: 10m]
>           -d, --difficulty-initial <DIFFICULTY_INITIAL>
>               initial difficulty to start with [default: 15]
>           -t, --txpb <TXPB>
>               max amount of transactions per block [default: 20]
>           -w, --wallet <WALLET>
>               address of wallet to mine for [default: ]
>           -r, --reward <REWARD>
>               starting block reward [default: 100]
>               
>               --halving <HALVING>
>               blocks until halving [default: 100]
>           -f, --fee <FEE>
>               percentage of fee [default: 5]
>           -c, --checklock <CHECKLOCK>
>               lock sync request after syncing for x blocks [default: 3]
>           -s, --sync
>               sync from entry node
>      -h, --help
>               Print help

1. Grep your freshly generated address and let's run the node: 

        cargo run --bin node --release -- -g -e "30s" -d 12 -w 494A4mrmVgJUMDZJRbgbwALWQPUuu5cKM8m8DceovGDmLFR

    Now you'll see a perfectly fine running node.
    
        [+] MINER - mining...
        [+] MINER - received skip signal
        [+] MINER - nonce found: 5033798721166985109
        [+] MINER - network accepted block
        [+] MINER - block added:

        > Index: 1
        > Timestamp: 1719606119
        > Previous Hash: 0a5272bdf0111c1286278f652d0c4095a31676807c806af23b76c7b9cb3b8373
        > Nonce: 5033798721166985109
        > Hash: 00000fe28cf909338708f86e329afb08a9850ee3bd4adf5a58b0ca00869328a4
        > Transactions:

            - Source: jNcc7CuwJ7xrDJKehFXWkiwhwaDCPCxoJPb1ixQ6gxJZj
            - Destination: 494A4mrmVgJUMDZJRbgbwALWQPUuu5cKM8m8DceovGDmLFR
            - Timestamp: 1719606116
            - Value: 100
            - Fee: 0

        [+] MINER - mining block:
        > Index: 2
        > Timestamp: 1719606119
        > Previous Hash: 00000fe28cf909338708f86e329afb08a9850ee3bd4adf5a58b0ca00869328a4
        > Nonce: 0
        > Hash:
        > Transactions:

            - Source: jNcc7CuwJ7xrDJKehFXWkiwhwaDCPCxoJPb1ixQ6gxJZj
            - Destination: 494A4mrmVgJUMDZJRbgbwALWQPUuu5cKM8m8DceovGDmLFR
            - Timestamp: 1719606119
            - Value: 100
            - Fee: 0

        [+] MINER - mining...

    For the args I used to run the node, here an explaination and some tips of the most important ones:

    - `-g` - simply sais that it's the initial node, creating the first block of the chain
    - `-e "30s"` - for bitcoin it's actually 10 minutes, which is the default value for CatCoin too, but to let blocks mine faster I set it to aim for 30 seconds per block
    - `-d 12` - this is the initial difficulty target, depending on how strong your computer is you might want to adjust it to less to mine the first two blocks faster or increase it to mine longer, but for me 12 is relatively fast

2. Since a cryptocurrency isn't made out of one node, you might want to run more nodes which requires you to generate more address if you want to mine on different ones. Simply run another node:

        cargo run --bin node --release -- --sync -p 8001 -w 22FavBpKuh6TKMYny8ySiA9JvtLLx2YhvxpYXL3ekH1393E

    You can run as many nodes as you want, but I won't recommend that depending on the amount of cores of your CPU. 

# What is different?

This cryptocurrency is meant to run locally on one computer, so the p2p network isn't designed to operate on a large amount of nodes.

For the p2p network all of the nodes are connected with each other unlike Bitcoin, where a node is connected with only 5 other nodes. 

But something positive this network structure comes with is that transactions are on the blockchain for 100%. 

To compare it to Bitcoin, which was a reference to me, you should wait a few days to be sure the transaction didn't end up on a sidechain.

Another difference is the fee, because for Bitcoin the size of the transaction is affecting the fee which makes sense because bitcoin supports smart contracts.

CatCoin on the other hand is calculating the fee simply based on the value of the transaction which is by default 5%.

*Funfact:* I don't know how my cryptocurrency is handling a situation where every node has a different chain, but it does in some way...

