use cat_coin::{blockchain::*, comm::*, utils::*};
use clap::Parser;
use num_bigint::BigUint;
use rand::{seq::SliceRandom, thread_rng};
use serde_json::json;
use std::{
    io::Read,
    net::{Shutdown, TcpListener},
    process::exit,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
};

#[derive(Parser, Debug)]
struct Args {
    /// address of node
    #[arg(short, long, default_value_t = String::from("127.0.0.1"))]
    ip: String,

    /// port of node
    #[arg(short, long, default_value_t = 8000)]
    port: u16,

    /// create genisis block
    #[arg(short, long, default_value_t = false)]
    genisis: bool,

    /// entry node to join the network
    #[arg(short, long, default_value_t = String::from("127.0.0.1:8000"))]
    entry: String,

    /// hash difficulty
    #[arg(short, long, default_value_t = 14)]
    difficulty: u8,
}

fn main() {
    // get args
    let args = Args::parse();

    // check args
    if args.difficulty < 1 || args.difficulty > 71 {
        eprintln!("[#] ARGS - invalid difficulty (allowed: 1 - 71)");
        exit(1);
    }
    // format address
    let addr = format!("{}:{}", args.ip, args.port);

    // construct mutex objects
    let difficulty = Arc::new(Mutex::new(args.difficulty));
    let peers = Arc::new(Mutex::new(Vec::<String>::new()));
    let transactionpool = Arc::new(Mutex::new(TransactionPool::new()));
    let blockchain = match args.genisis {
        true => Arc::new(Mutex::new(BlockChain::new_with_genisis())),
        false => Arc::new(Mutex::new(BlockChain::new())),
    };

    // get blockchain from another node
    if !args.genisis && check_addr(&args.entry) {
        match blockchain.lock().unwrap().sync(&args.entry) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN:SYNC - failed check error: {}", e);
                exit(1);
            }
        }
    // if no entry node specified
    } else if !args.genisis {
        eprintln!("[#] SYNC - no entry node specified");
        exit(1);
    }

    // synchronizing transaction pool
    if !args.genisis {
        println!("[+] SYNC - updating transaction pool");

        // craft request
        let req = Request {
            dtype: Dtype::GetTransactionPool,
            data: "",
        };
        // send request
        let stream = match request(&args.entry, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - request transaction pool error: {}", e);
                exit(1);
            }
        };
        // receive data
        let response: Response<Vec<serde_json::Value>> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - receive transaction pool error: {}", e);
                exit(1);
            }
        };
        let transactions = response.res;

        // update transactions if any
        if transactions.len() > 0 {
            // construct transactions from json
            let mut rcvd_pool: Vec<Transaction> = Vec::new();
            for i in transactions {
                // construct Transaction
                match Transaction::from_json(&i) {
                    Ok(n) => &rcvd_pool.push(n),
                    Err(_) => continue,
                };
            }

            // validate transactions
            let mut rm: Vec<Transaction> = Vec::new();
            for t in &rcvd_pool {
                match t.validate() {
                    Ok(_) => continue,
                    Err(_) => rm.push(t.clone()),
                }
            }

            // log
            if rm.len() > 0 {
                println!("[!] SYNC - invalid transactions removed: {}", rm.len());
            }

            // remove invalid transactions & update transaction pool
            let mut pool = transactionpool.lock().unwrap();
            *pool = TransactionPool::from_vec(&rcvd_pool);
            println!("[+] SYNC - update transaction pool successful");
        } else {
            println!("[+] SYNC - no update required");
        }

        // update list of peers
        println!("[+] SYNC - updating list of peers");

        // craft request
        let req = Request {
            dtype: Dtype::GetPeers,
            data: "",
        };
        // send request
        let stream = match request(&args.entry, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - request list of peers error: {}", e);
                exit(1);
            }
        };
        // receive list of peers
        let response: Response<Vec<String>> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - receive list of peers error: {}", e);
                exit(1);
            }
        };
        let mut peers_rcved = response.res;

        // check peers
        let mut rm: Vec<String> = Vec::new();
        for peer in &peers_rcved {
            if !check_addr(&peer) {
                rm.push(peer.to_owned());
            }
        }
        // log
        if rm.len() > 0 {
            println!("[!] SYNC - invalid peers removed: {}", rm.len());
        }
        // remove invalid peers
        peers_rcved = subtract_vec(peers_rcved, rm);
        peers_rcved.push(args.entry.clone()); // add entry node

        // broadcast address to peers
        println!("[+] SYNC - broadcasting address");
        let (responses, rm) = broadcast::<AddPeerResponse>(&peers_rcved, Dtype::AddPeer, &addr);
        println!("DEBUG - AddPeer responses: {:?}", responses); // DEBUG

        // remove unreachable peers & update peers
        let mut peers = peers.lock().unwrap(); // lock mutex
        *peers = subtract_vec(peers_rcved, rm); // update peers
        println!("[+] SYNC - update list of peers successful");

        // synchronize difficulty
        println!("[+] SYNC - updating difficulty");

        // craft request
        let req = Request {
            dtype: Dtype::GetDifficulty,
            data: "",
        };
        // connect to node
        let stream = match request(&args.entry, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - request difficulty error: {}", e);
                exit(1);
            }
        };
        // receive difficulty
        let response: Response<u8> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - receive difficulty error: {}", e);
                exit(1);
            }
        };
        // check difficulty
        // TODO: check difficulty
        // update difficulty
        *difficulty.lock().unwrap() = response.res;
        println!("[+] SYNC - update difficulty successful")
    }

    // DEBUG
    println!(
        "DEBUG - blockchain: {:?}",
        blockchain.lock().unwrap().get_chain()
    );

    // log stuff
    println!("[+] SETUP - listening on: {}", addr);
    println!(
        "[+] SETUP - genisis hash: {}",
        blockchain.lock().unwrap().get_latest().unwrap().hash
    );
    println!("[+] MINER - target value: {:?}", {
        get_difficulty(*difficulty.lock().unwrap())
    });

    // construct MineController and start mining
    let mine_controller = Arc::new(MineController::new(
        &blockchain,
        &transactionpool,
        &peers,
        &difficulty,
    ));
    mine_controller.run();

    // create listener
    let listener: TcpListener = TcpListener::bind(addr).unwrap();
    for stream in listener.incoming() {
        // clone mutex instances
        let difficulty = Arc::clone(&difficulty);
        let peers = Arc::clone(&peers);
        let transactionpool = Arc::clone(&transactionpool);
        let blockchain = Arc::clone(&blockchain);
        let mine_controller = Arc::clone(&mine_controller);

        // spawn thread and handle connection
        let _ = thread::spawn(move || {
            // overwriting stream
            let mut stream = stream.unwrap();

            // create buffer and receive data
            let mut buffer = String::new();
            stream.read_to_string(&mut buffer).unwrap();
            stream.shutdown(Shutdown::Read).unwrap();

            {
                // DEBUG
                match serde_json::from_str::<Request<String>>(&buffer) {
                    Ok(n) => {
                        println!("DEBUG:\n> Dtype: {:?}\n> Data: {}", n.dtype, n.data);
                        println!("RAW: {}", buffer);
                    }
                    Err(e) => {
                        eprintln!("DEBUG - debug receive error: {}", e);
                        println!("RAW: {}", buffer);
                    }
                };
            }

            // load json from buffer
            let request: Request<String> = match serde_json::from_str(&buffer) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] LISTENER - receive data error: {}", e);
                    Request {
                        dtype: Dtype::Skip,
                        data: String::new(),
                    }
                }
            };

            match request.dtype {
                Dtype::AddPeer => {
                    let peer = request.data;

                    // check address
                    if !check_addr(&peer) {
                        respond(&stream, AddPeerResponse::FailedCheck);
                        eprintln!("[#] DTYPE:AddPeer - check failed");
                        return;
                    }
                    // add peer to list if not already contained
                    let mut peers = peers.lock().unwrap();
                    if !peers.contains(&peer) {
                        peers.push(peer);
                        respond(&stream, AddPeerResponse::Success);

                    // if already in list
                    } else {
                        respond(&stream, AddPeerResponse::AlreadyExist);
                    }
                }

                Dtype::AddTransaction => {
                    // load data as json
                    let data = match serde_json::Value::from_str(&request.data) {
                        Ok(n) => n,
                        Err(e) => {
                            respond(&stream, AddTransactionResponse::ParsingError);
                            eprintln!("[#] DTYPE:AddTransaction - parse to json error: {}", e);
                            return;
                        }
                    };
                    // construct transaction
                    let mut transaction = match Transaction::from_json(&data) {
                        Ok(n) => n,
                        Err(e) => {
                            respond(&stream, AddTransactionResponse::ConstructionError);
                            eprintln!("[#] DTYPE:AddTransaction - construction error: {:?}", e);
                            return;
                        }
                    };
                    // check transaction
                    match transaction.validate() {
                        Ok(_) => {}
                        Err(e) => {
                            respond(&stream, AddTransactionResponse::FailedCheck);
                            eprintln!("[#] DTYPE:AddTransaction - check failed: {:?}", e);
                            return;
                        }
                    }
                    // broadcast transaction
                    let mut peers = peers.lock().unwrap();
                    if transaction.broadcast {
                        transaction.broadcast = false; // disable broadcast
                        let (_, failed) = broadcast::<AddTransactionResponse>(
                            &peers,
                            Dtype::AddTransaction,
                            &transaction.as_json().to_string(),
                        ); // broadcast
                        *peers = subtract_vec(peers.to_vec(), failed); // remove unreachable peers
                    }
                    // add transaction to pool
                    let mut pool = transactionpool.lock().unwrap();
                    match pool.add(&transaction) {
                        Ok(_) => {
                            println!("[+] DTYPE:AddTransaction - added:\n{}", transaction);
                            respond(&stream, AddTransactionResponse::Success);
                        }
                        Err(e) => {
                            respond(&stream, AddTransactionResponse::DuplicatedTransaction);
                            eprintln!("[#] DTYPE:AddTransaction - transaction not added: {:?}", e);
                        }
                    }
                }

                // TODO: prevent dos attack here
                // TODO: resync because of reason!?!
                // TODO: stop miner entirely and start after resync
                Dtype::CheckBlockchain => {
                    respond(&stream, CheckBlockchainResponse::Success);
                    let map = collect_map(&peers.lock().unwrap(), Dtype::GetLatestHash, "");
                    let latest_hash = match get_key_by_vec_len(map.clone()) {
                        Some(n) => n,
                        None => return,
                    };

                    let mut chain = blockchain.lock().unwrap();
                    if latest_hash != chain.get_latest().unwrap().hash {
                        loop {
                            let peer = map[&latest_hash].choose(&mut thread_rng()).unwrap();
                            match chain.sync(&peer) {
                                Ok(_) => break,
                                Err(e) => {
                                    eprintln!("[#] BLOCKCHAIN:SYNC - failed check error: {}", e);
                                    continue;
                                }
                            }
                        }
                    }
                }

                Dtype::GetBlock => {
                    // lock chain & parse index
                    let chain = blockchain.lock().unwrap();
                    let length = chain.get_chain().len();
                    let idx = {
                        // if requested latest block
                        if request.data == "-1" {
                            length - 1
                        } else {
                            // otherwise parse index
                            match request.data.parse::<usize>() {
                                Ok(n) => n,
                                Err(e) => {
                                    respond(&stream, "");
                                    eprintln!("[#] DTYPE:GetBlock - parse index error: {}", e);
                                    return;
                                }
                            }
                        }
                    };
                    // check if index in range
                    if idx > chain.get_chain().len() - 1 {
                        respond(&stream, "");
                    }
                    // get block and respond
                    match chain.get(idx) {
                        Some(n) => {
                            let json = json!({
                                "block": n.as_json(),
                                "len": length,
                            });
                            respond(&stream, json.to_string());
                        }
                        None => respond(&stream, ""),
                    };
                }

                Dtype::GetBlockchain => {
                    let chain = blockchain.lock().unwrap(); // lock blockchain
                    let blocks: Vec<String> = chain
                        .get_chain()
                        .iter()
                        .map(|x| x.as_json().to_string())
                        .collect(); // convert blocks to json
                    respond(&stream, blocks); // respond blockchain
                }

                Dtype::GetDifficulty => {
                    respond(&stream, difficulty.lock().unwrap());
                }

                Dtype::GetLatestHash => match blockchain.lock().unwrap().get_latest() {
                    Ok(n) => respond(&stream, n.hash),
                    Err(_) => respond(&stream, ""),
                },

                Dtype::GetPoolHash => match merkle_hash(
                    transactionpool
                        .lock()
                        .unwrap()
                        .pool
                        .iter()
                        .map(|x| x.hash.clone())
                        .collect(),
                ) {
                    Some(n) => respond(&stream, n),
                    None => respond(&stream, ""),
                },

                Dtype::GetPeers => {
                    respond(&stream, peers.lock().unwrap());
                }

                Dtype::GetTransactionPool => {
                    let pool: Vec<serde_json::Value> = transactionpool
                        .lock()
                        .unwrap()
                        .pool
                        .iter()
                        .map(|x| x.as_json())
                        .collect();
                    respond(&stream, pool);
                }

                Dtype::PostBlock => {
                    // load data as json
                    let data = match serde_json::Value::from_str(&request.data) {
                        Ok(n) => n,
                        Err(e) => {
                            respond(&stream, PostBlockResponse::ParsingJsonError);
                            eprintln!("[#] DTYPE:PostBlock - parse to json: {:?}", e);
                            return;
                        }
                    };
                    // construct block
                    let block = match Block::from_json(&data) {
                        Ok(n) => n,
                        Err(e) => {
                            respond(&stream, PostBlockResponse::ConstructionError);
                            eprintln!("[#] DTYPE:PostBlock - construction error: {:?}", e);
                            return;
                        }
                    };
                    {
                        // debug
                        println!("\n\nReceived:\n{}\n", block);
                        println!(
                            "\n\nCurrent:\n{}\n",
                            mine_controller.current_block.lock().unwrap()
                        );
                    }
                    // parse hash difficulty
                    let val = match BigUint::parse_bytes(block.hash.as_bytes(), 16) {
                        Some(n) => n,
                        None => {
                            respond(&stream, PostBlockResponse::ParsingHashValError);
                            eprintln!("[#] DTYPE:PostBlock - parse hash value error");
                            return;
                        }
                    };
                    {
                        // check hash difficulty
                        if val > get_difficulty(*difficulty.lock().unwrap()) {
                            respond(&stream, PostBlockResponse::MismatchHashDifficulty);
                            eprintln!("[#] DTYPE:PostBlock - invalid hash difficulty");
                            return;
                        }
                    }
                    // check block
                    match block.validate() {
                        Ok(_) => println!("[+] DTYPE:PostBlock - block valid"),
                        Err(e) => {
                            respond(&stream, PostBlockResponse::ValidationError);
                            eprintln!("[#] DTYPE:PostBlock - block invalid: {:?}", e);
                            return;
                        }
                    }
                    {
                        // check if block matches currently mined block
                        if block != *mine_controller.current_block.lock().unwrap() {
                            respond(&stream, PostBlockResponse::MismatchCurrentlyMinedBlock);
                            eprintln!(
                                "[#] DTYPE:PostBlock - block doesn't match currently mined block"
                            );
                            return;
                        }
                    }
                    // add block to chain
                    match blockchain.lock().unwrap().add_block(&block) {
                        Ok(_) => {
                            mine_controller.skip(); // skip currently mined block
                            println!("[+] DTYPE:PostBlock - add block to chain succeed");
                            respond(&stream, PostBlockResponse::Success);
                        }
                        Err(e) => {
                            eprintln!("[#] DTYPE:PostBlock - add block to chain error: {:?}", e);
                            respond(&stream, PostBlockResponse::AddToChainError);
                        }
                    }
                }

                Dtype::Skip => {}
            }
        });
    }
}

// > TODO: continue working on resyncing blockchain if block doesn't match
// TODO: don't forget to also resync transaction pool
// TODO: fix doesn't mine correct block after resync of blockchain
// TODO: fix resync if received block is invalid, but blockchain is valid, it's resyncing anyway
// TODO: make the node only resyncing until it's valid again
// TODO: make node broadcast transaction even it's invalid
// TODO: check what happens if multiple nodes receive the same transaction at the same time
// TODO: how are coins generated?
// TODO: check if miner is compiled -> if not then compile it and run the binary instead of cargo
// TODO: limit amount of transactions (or rather size of blocks)
// TODO: check if chain is still valid sometimes (every 10 blocks when the time was measured and
//       the difficulty was adjusted)
// TODO: make difficulty adjustable (maybe by amount of miners)
// TODO: replace str method of blockchain related object with fmt::Display
// TODO: add pool feature where nodes have ID's to mine more efficiently
// TODO: add Docs to functions
// TODO: improve returning errors by using Result<val, Error> instead of Result<val, ()>
// TODO: improve logging
// TODO: replace sha256 regex checks with the function to do that
// TODO: remove everyhthing with //debug comment
// TODO: cleanup imports
// TODO: remove warnings by cargo
// TODO: real signatures and real wallet addresses
// TODO: multi signatures
// TODO: block reward
// TODO: blurring for anonymity
// Resource: https://medium.com/learning-lab/how-cryptocurrencies-work-technical-guide-95950c002b8f
//
// TODO: in far future:
// - the miner should be run as release? (so the command might not be optimal)
//
// TODO: Optional:
// - encrypt traffic between nodes?
// - save blockchain to continue later?
// - full and half nodes..?
