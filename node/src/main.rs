extern crate node;
extern crate num_bigint;
extern crate rand;
extern crate serde_json;
use node::{
    blockchain::*,
    comm::*,
    share::{self, COINBASE, FEE},
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
    share::init();
    let args = unsafe { share::ARGS.get().unwrap().to_owned() };
    let addr = share::ADDR.get().unwrap().to_string();
    if !args.genisis && args.sync {
        // synchronize args
        match sync_args(&args.entry) {
            Ok(n) => match n {
                SyncState::Ready => (),
                _ => panic!("[#] ARGS:SYNC - synchronization failed: {:?}", n),
            },
            Err(e) => {
                eprintln!("[#] ARGS:SYNC - synchronization error: {}", e);
                exit(1);
            }
        }
    }
    // get updated args
    let args = unsafe { share::ARGS.get().unwrap().to_owned() };

    // compile miner
    match compile_miner() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[#] MINER:SETUP - compilation error: {}", e);
            exit(1);
        }
    }
    // construct mutex objects
    let blockchain = match BlockChain::new() {
        Ok(mut n) => {
            // add genisis block if necessary
            if args.genisis {
                match n.create_genisis() {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("[#] BLOCKCHAIN:SETUP - create genisis block error: {}", e);
                        exit(1);
                    }
                }
            }
            n
        }
        Err(e) => {
            eprintln!("[#] BLOCKCHAIN:SETUP - load blockchain error: {}", e);
            exit(1);
        }
    };
    let blockchain = Arc::new(Mutex::new(blockchain));
    let last_check = Arc::new(Mutex::new(0_u64));
    let difficulty = Arc::new(Mutex::new(args.difficulty));
    let peers = Arc::new(Mutex::new(Vec::<String>::new()));
    let transactionpool = Arc::new(Mutex::new(TransactionPool::new(args.tx_per_block)));

    // synchronize everything
    if args.sync && check_ip(&args.entry) {
        // synchronize peers
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
        // check if synchronization is needed
        let mut chain = blockchain.lock().unwrap();
        let (state, peers, idx) = match chain.check(&peers.lock().unwrap()) {
            Ok(n) => n,
            Err(e) => panic!("[#] BLOCKCHAIN:SYNC - check chain error: {}", e),
        };
        // choose peer
        let peer = match peers.choose(&mut thread_rng()) {
            Some(n) => n,
            None => &args.entry,
        };
        // synchronize blockchain if needed
        if state == SyncState::Needed {
            match chain.sync(peer, idx) {
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
        }
        // synchronize transaction pool
        match transactionpool.lock().unwrap().sync(peer) {
            Ok(n) => match n {
                SyncState::Ready => (),
                _ => panic!("[#] TRANSACTIONPOOL:SYNC - synchronization failed: {:?}", n),
            },
            Err(e) => {
                eprintln!("[#] TRANSACTIONPOOL:SYNC - synchronization error: {}", e);
                exit(1);
            }
        }
    }

    // construct MineController and start mining
    let mine_controller = Arc::new(MineController::new(
        &args.wallet,
        &args.entry,
        &blockchain,
        &transactionpool,
        &peers,
        &difficulty,
    ));
    // start mining
    mine_controller.run(args.genisis, args.sync);

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
            blockchain.lock().unwrap().last().unwrap().unwrap().hash
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
        let last_check = Arc::clone(&last_check);

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
                    if !check_ip(&peer) {
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
                    {
                        // check transaction
                        match transaction.validate(&blockchain.lock().unwrap()) {
                            Ok(_) => {}
                            Err(e) => {
                                respond(&stream, AddTransactionResponse::FailedCheck);
                                eprintln!("[#] DTYPE:AddTransaction - check failed: {:?}", e);
                                return;
                            }
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

                Dtype::CheckSync => {
                    {
                        // check if synced too recently
                        let index = mine_controller.current_block.lock().unwrap().index;
                        let mut last = last_check.lock().unwrap();
                        if index < (*last + args.checklock as u64) {
                            respond(&stream, CheckSyncResponse::Blocked);
                            return;
                        } else {
                            respond(&stream, CheckSyncResponse::OK);
                            *last = index;
                        }
                    }
                    // synchronize node if necessary
                    let peers = peers.lock().unwrap();
                    {
                        // blockchain
                        let mut chain = blockchain.lock().unwrap();
                        let (state, peers, idx) = match chain.check(&peers) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[#] DTYPE:CheckSync - check blockchain error: {:?}", e);
                                (SyncState::Error, vec![], 0)
                            }
                        };
                        if state != SyncState::Error {
                            match state {
                                SyncState::Fine => println!("[+] BLOCKCHAIN - state: fine"),
                                SyncState::Needed => {
                                    // choose peer
                                    let peer = match peers.choose(&mut thread_rng()) {
                                        Some(n) => n,
                                        None => &args.entry,
                                    };
                                    // sync blockchain
                                    match chain.sync(peer, idx) {
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

                Dtype::GetArgs => respond(&stream, args.as_json().to_string()),

                Dtype::GetBlock => {
                    // lock chain & parse index
                    let chain = blockchain.lock().unwrap();
                    let length = chain.len();
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
                        if idx > chain.len() - 1 {
                            respond(&stream, "");
                        }
                        // get block and respond
                        match chain.get(idx as u64) {
                            Ok(n) => match n {
                                Some(n) => {
                                    println!("DEBUG - requested block:\n{}", n); // DEBUG
                                    respond(
                                        &stream,
                                        json!({"block": n.as_json(), "len": length}).to_string(),
                                    )
                                }
                                None => respond(&stream, " "),
                            },
                            Err(e) => {
                                eprintln!(
                                    "DTYPE:GetBlock - retrieve block from database error: {}",
                                    e
                                );
                                respond(&stream, "");
                            }
                        };
                    }
                }

                Dtype::GetCoinbaseAddress => respond(&stream, COINBASE.get().unwrap()),

                Dtype::GetFee => respond(&stream, FEE.get().unwrap()),

                Dtype::GetPoolHash => match merkle_hash(
                    transactionpool
                        .lock()
                        .unwrap()
                        .pool
                        .iter()
                        .map(|x| hash_str(x.to_string().as_bytes()))
                        .collect(),
                ) {
                    Some(n) => respond(&stream, n),
                    None => respond(&stream, ""),
                },

                Dtype::GetPeers => respond(&stream, peers.lock().unwrap()),

                Dtype::GetTransactions => {
                    // parse received pattern
                    let pattern: Vec<u8> = match serde_json::from_str(&request.data) {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[#] DTYPE:GetTransactions - parse error: {}", e);
                            respond::<Vec<String>>(&stream, Vec::new());
                            return;
                        }
                    };
                    let chain = { blockchain.lock().unwrap().clone() };

                    // retrieve transactions based on the pattern
                    let transactions: Vec<String> = match chain.get_txs_by_pat(&pattern) {
                        Ok(n) => {
                            // parse transaction to json
                            n.iter().map(|x| x.as_json().to_string()).collect()
                        }
                        Err(e) => {
                            eprintln!("[#] DTYPE:GetTransactions - retrieve transactions by pattern error: {}", e);
                            respond::<Vec<String>>(&stream, Vec::new());
                            return;
                        }
                    };
                    respond(&stream, transactions);
                }

                Dtype::GetTransactionPool => {
                    let lock = transactionpool.lock().unwrap();
                    let pool: Vec<String> =
                        lock.pool.iter().map(|x| x.as_json().to_string()).collect();
                    respond(&stream, pool);
                }

                Dtype::GetTransactionsPerBlock => {
                    respond(&stream, transactionpool.lock().unwrap().tx_per_block);
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
                    {
                        // check block
                        match block.validate(&blockchain.lock().unwrap()) {
                            Ok(_) => println!("[+] DTYPE:PostBlock - block valid"),
                            Err(e) => {
                                respond(&stream, PostBlockResponse::ValidationError);
                                eprintln!("[#] DTYPE:PostBlock - block invalid: {:?}", e);
                                return;
                            }
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

// TODO: other todos
// TODO: with every mined block a miner process is spawned but seems to be not deleted???
//       no matter what, I don't think that's beneficial for a long chain and many nodes
// TODO: no transactions of amount 0 or same src and dst
// TODO: optimize miner command
// TODO: partial transactions request (balance) - see client
// TODO: make difficulty automatically adjusted
// TODO: add Docs to functions
// TODO: client
// TODO: improve logging -> write a logger or at least generalize the logging
// TODO: remove debug print statements
// TODO: GitHub licency
// TODO: block from slice?
