use cat_coin::{
    args::{self, ADDR, ARGS},
    blockchain::*,
    comm::*,
    utils::*,
};
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

fn main() {
    // get args
    args::init();
    let args = ARGS.get().unwrap().to_owned();
    let addr = ADDR.get().unwrap().to_string();

    // construct mutex objects
    let difficulty = Arc::new(Mutex::new(args.difficulty));
    let peers = Arc::new(Mutex::new(Vec::<String>::new()));
    let transactionpool = Arc::new(Mutex::new(TransactionPool::new(args.tx_per_block)));
    let blockchain = match args.genisis {
        true => Arc::new(Mutex::new(BlockChain::new_with_genisis())),
        false => Arc::new(Mutex::new(BlockChain::new())),
    };

    // synchronize blockchain
    if !args.genisis && check_addr(&args.entry) {
        match blockchain.lock().unwrap().sync(&args.entry) {
            Ok(n) => match n {
                SyncState::Ready => (),
                SyncState::Running => (),
                _ => panic!("[#] BLOCKCHAIN:SYNC - synchronization failed: {:?}", n),
            },
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN:SYNC - synchronization error: {}", e);
                exit(1);
            }
        }
    // if no entry node specified
    } else if !args.genisis {
        eprintln!("[#] BLOCKCHAIN:SYNC - no entry node specified");
        exit(1);
    }
    // synchronize transaction pool
    if !args.genisis {
        match transactionpool.lock().unwrap().sync(&args.entry) {
            Ok(n) => match n {
                SyncState::Ready => (),
                _ => panic!("[#] TRANSACTIONPOOL:SYNC - synchronization failed: {:?}", n),
            },
            Err(e) => {
                eprintln!("[#] TRANSACTIONPOOL:SYNC - synchronization error: {}", e);
                exit(1);
            }
        }
        // update list of peers
        match sync_peers(&args.entry, &addr, &peers) {
            Ok(n) => match n {
                SyncState::Ready => (),
                _ => panic!("[#] PEERS:SYNC - synchronization failed: {:?}", n),
            },
            Err(e) => {
                eprintln!("[#] PEERS:SYNC - synchronization error: {}", e);
                exit(1);
            }
        }
        // synchronize difficulty
        match sync_difficulty(&args.entry, &difficulty) {
            Ok(n) => match n {
                SyncState::Ready => (),
                _ => panic!("[#] DIFFICULTY:SYNC - synchronization failed: {:?}", n),
            },
            Err(e) => {
                eprintln!("[#] DIFFICULTY:SYNC - synchronization error: {}", e);
                exit(1);
            }
        }
    }

    // construct MineController and start mining
    let mine_controller = Arc::new(MineController::new(
        &args.entry,
        &blockchain,
        &transactionpool,
        &peers,
        &difficulty,
    ));
    // start mining
    mine_controller.run(args.genisis);

    {
        // DEBUG
        println!(
            "DEBUG - TransactionPool:\n{}",
            transactionpool.lock().unwrap()
        );
    }

    // log stuff
    {
        println!("[+] SETUP - listening on: {}", addr);
        println!(
            "[+] SETUP - genisis hash: {}",
            blockchain.lock().unwrap().get_latest().unwrap().hash
        );
        println!("[+] MINER - target value: {:?}", {
            difficulty_from_u8(*difficulty.lock().unwrap())
        });
    }

    // create listener
    let listener: TcpListener = TcpListener::bind(&addr).unwrap();
    for stream in listener.incoming() {
        // clone variables instances
        let addr = addr.clone();
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
                        addr,
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

                // nodes have received the transaction too
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
                    {
                        // broadcast peers
                        let mut peers = peers.lock().unwrap();
                        if !peers.contains(&request.addr) || transaction.broadcast {
                            transaction.broadcast = false; // update transaction
                            let (_, failed) = broadcast::<AddTransactionResponse>(
                                &peers,
                                Dtype::AddTransaction,
                                &transaction.as_json().to_string(),
                            );
                            // remove unreachable peers
                            *peers = subtract_vec(peers.to_vec(), failed);
                        }
                    }
                    // check transaction
                    match transaction.validate() {
                        Ok(_) => {}
                        Err(e) => {
                            respond(&stream, AddTransactionResponse::FailedCheck);
                            eprintln!("[#] DTYPE:AddTransaction - check failed: {:?}", e);
                            return;
                        }
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
                Dtype::CheckSync => {
                    respond(&stream, CheckSyncResponse::OK);

                    // synchronize node if necessary
                    let peers = peers.lock().unwrap();
                    {
                        // blockchain
                        let mut chain = blockchain.lock().unwrap();
                        let (state, peers) = match chain.check(&peers) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[#] DTYPE:CheckSync - check blockchain error: {:?}", e);
                                (SyncState::Error, vec![])
                            }
                        };
                        if state != SyncState::Error {
                            match state {
                                SyncState::Fine => println!("[+] BLOCKCHAIN - state: fine"),
                                SyncState::Needed => {
                                    // sync blockchain
                                    match chain.sync(peers.choose(&mut thread_rng())
                                        .expect("[#] DTYPE:CheckSync - random peer for blockchain sync error")) {
                                        Ok(n) => match n {
                                            SyncState::Ready => (),
                                            SyncState::Running => (),
                                            _ => panic!("[#] BLOCKCHAIN:SYNC - synchronization failed: {:?}", n),
                                        },
                                        Err(e) => eprintln!("[#] BLOCKCHAIN:SYNC - synchronization error: {}", e),
                                    };
                                }
                                _ => (),
                            }
                        }
                    }
                    {
                        // transactionpool
                        let mut pool = transactionpool.lock().unwrap();
                        let (state, peers) = match pool.check(&peers) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!(
                                    "[#] DTYPE:CheckSync - check transactionpool error: {:?}",
                                    e
                                );
                                (SyncState::Error, vec![])
                            }
                        };
                        if state != SyncState::Error {
                            match state {
                                SyncState::Fine => println!("[+] TRANSACTIONPOOL - state: fine"),
                                SyncState::Needed => {
                                    // sync transactionpool
                                    match pool.sync(peers.choose(&mut thread_rng())
                                        .expect("[#] DTYPE:CheckSync - random peer for transactionpool sync error")) {
                                        Ok(n) => match n {
                                            SyncState::Ready => (),
                                            _ => panic!("[#] TRANSACTIONPOOL:SYNC - synchronization failed: {:?}", n),
                                        },
                                        Err(e) => eprintln!("[#] TRANSACTIONPOOL:SYNC - synchronization error: {}", e),
                                    };
                                }
                                _ => (),
                            }
                        }
                    }
                    {
                        // minecontroller
                        let (state, peers) = match mine_controller.check(&peers) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!(
                                    "[#] DTYPE:CheckSync - check minecontroller error: {:?}",
                                    e
                                );
                                (SyncState::Error, vec![])
                            }
                        };
                        if state != SyncState::Error {
                            match state {
                                SyncState::Fine => println!("[+] MINECONTROLLER - state: fine"),
                                SyncState::Needed => {
                                    // set sync address
                                    *mine_controller.sync_addr.lock().unwrap() = peers
                                        .choose(&mut thread_rng())
                                        .expect(
                                            "[#] DTYPE:CheckSync - random peer for minecontroller sync error",
                                        )
                                        .to_string();
                                    // sync minecontroller
                                    match mine_controller.sync(&mine_controller.current_block) {
                                        Ok(n) => match n {
                                            SyncState::Ready => (),
                                            _ => panic!("[#] MINECONTROLLER:SYNC - synchronization failed: {:?}", n),
                                        },
                                        Err(e) => eprintln!("[#] MINECONTROLLER:SYNC - synchronization error: {}", e),
                                    };
                                }
                                _ => (),
                            }
                        }
                    }
                }

                Dtype::GetBlock => {
                    // lock chain & parse index
                    let chain = blockchain.lock().unwrap();
                    let length = chain.get_chain().len();
                    if request.data == "-2" {
                        // currently mined block
                        let block = mine_controller.current_block.lock().unwrap().clone();
                        respond(&stream, block.as_json().to_string());
                    } else {
                        let idx = {
                            if request.data == "-1" {
                                // latest block
                                length - 1
                            } else {
                                // any other block
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
                                println!("DEBUG - get block: {}", json.to_string());
                                respond(&stream, json.to_string());
                            }
                            None => respond(&stream, ""),
                        };
                    }
                }

                Dtype::GetBlockchain => {
                    let chain = blockchain.lock().unwrap();
                    let blocks: Vec<String> = chain
                        .get_chain()
                        .iter()
                        .map(|x| x.as_json().to_string()) // parse blocks to json
                        .collect();
                    respond(&stream, blocks);
                }

                Dtype::GetDifficulty => {
                    respond(&stream, difficulty.lock().unwrap());
                }

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
                    let pool: Vec<String> = transactionpool
                        .lock()
                        .unwrap()
                        .pool
                        .iter()
                        .map(|x| x.as_json().to_string())
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
                        if val > difficulty_from_u8(*difficulty.lock().unwrap()) {
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
                            println!("[+] DTYPE:PostBlock - add block to chain succeed");
                            respond(&stream, PostBlockResponse::Success);
                        }
                        Err(e) => {
                            eprintln!("[#] DTYPE:PostBlock - add block to chain error: {:?}", e);
                            respond(&stream, PostBlockResponse::AddToChainError);
                        }
                    }
                    mine_controller.skip(); // skip currently mined block
                }

                Dtype::Skip => {}
            }
        });
    }
}

// > TODO: implement synchronization of txpb in GetTransactionPool Dtype
// TODO: other todos
// TODO: make the node only resyncing until it's valid again
// TODO: store the blockchain in a file or maybe multiple files
// TODO: coinbase transaction - generate coins
// TODO: make difficulty automatically adjustable (maybe by amount of miners)
// TODO: add pool feature where nodes have ID's to mine more efficiently
// TODO: add Docs to functions
// TODO: improve logging -> write a logger
// TODO: real signatures and real wallet addresses
// TODO: multi signatures
// TODO: blurring for anonymity
// TODO: web server + website for hot wallet
//
// TODO: in far future:
// - check if miner is compiled -> if not then compile it and run the binary instead of cargo
// - remove debug print statements
//
// TODO: Optional:
// - if one thread panics or exits the other one should stop too
// - encrypt traffic between nodes?
// - full and half nodes..?
//
// TODO: configs that should be available:
// - amount of transactions
// - sleep time between reading stdout / stdin of miner
// - time that should be aimed for every block
