mod lib;

use crate::lib::{
    broadcast, check_addr, get_difficulty, respond_code, respond_json, send_string, subtract_vec,
    Block, BlockChain, MineController, Transaction, TransactionPool,
};
use clap::Parser;
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::json;
use std::{
    io::Read,
    net::{Shutdown, TcpListener, TcpStream},
    process::exit,
    sync::{Arc, Mutex},
    thread,
};

#[derive(Deserialize, Debug)]
struct RequestReceiver {
    dtype: i8,
    data: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct ResponseReceiver {
    res: i8,
    data: serde_json::Value,
}

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
        println!("[+] SYNC - updating blockchain");

        // connect to node
        let stream = match TcpStream::connect(&args.entry) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - connection error: {}", e);
                exit(1);
            }
        };

        // request and receive blockchain
        let buffer = match send_string(&stream, "{\"dtype\":5, \"data\":{}}".to_string()) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - receive chain error: {}", e);
                exit(1);
            }
        };

        // load json from buffer
        let json: ResponseReceiver = match serde_json::from_str(&buffer) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - parsing blockchain error: {}", e);
                exit(1);
            }
        };

        // construct blocks from json
        let rcvd_chain = json.data.as_array().unwrap().to_vec();
        let mut chain: Vec<Block> = Vec::new();
        for i in rcvd_chain {
            // construct block
            match Block::from_json(&i) {
                Ok(n) => chain.push(n),
                Err(e) => {
                    eprintln!("[#] SYNC - parsing block error: {:?}", e);
                    exit(1);
                }
            };
        }

        // add blocks to chain
        let mut blockchain = blockchain.lock().unwrap();
        blockchain.set_chain(chain);
        println!("[+] SYNC - blockchain update successful");

    // if no entry node specified
    } else if !args.genisis {
        eprintln!("[#] SYNC - no entry node specified");
        exit(1);
    }

    // synchronizing transaction pool & list of peers
    if !args.genisis {
        // get transaction pool
        println!("[+] SYNC - updating transaction pool");

        // connect to node
        let stream = match TcpStream::connect(&args.entry) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - connection error: {}", e);
                exit(1);
            }
        };

        // receive transaction pool
        let buffer = match send_string(&stream, String::from("{\"dtype\": 3, \"data\":{}}")) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - receive transaction pool error: {}", e);
                exit(1);
            }
        };

        // load json from buffer
        let json: ResponseReceiver = match serde_json::from_str(&buffer) {
            Ok(n) => n,
            Err(e) => {
                respond_code(&stream, 1);
                eprintln!("[#] SYNC - failed parsing transaction pool: {}", e);
                exit(1);
            }
        };

        // cast json into vector
        let transactions = json.data.as_array().unwrap().to_vec();

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

        // get list of peers
        println!("[+] SYNC - updating list of peers");

        // connect to node
        let stream = match TcpStream::connect(&args.entry) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - connection error: {}", e);
                exit(1);
            }
        };

        // receive list of peers
        let buffer = match send_string(&stream, String::from("{\"dtype\": 1, \"data\":{}}")) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] SYNC - receive list of peers error: {}", e);
                exit(1);
            }
        };

        // load json from buffer
        let json: ResponseReceiver = match serde_json::from_str(&buffer) {
            Ok(n) => n,
            Err(e) => {
                respond_code(&stream, 1);
                eprintln!("[#] SYNC - failed parsing peers: {}", e);
                exit(1);
            }
        };

        // validate peers
        let mut peers = peers.lock().unwrap();
        *peers = json
            .data
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string().replace("\"", ""))
            .collect();

        // find invalid peers
        let mut rm: Vec<String> = Vec::new();
        for peer in peers.clone() {
            if !check_addr(&peer) {
                rm.push(peer);
            }
        }

        // log
        if rm.len() > 0 {
            println!("[!] SYNC - invalid peers removed: {}", rm.len());
        }

        // remove invalid peers
        *peers = subtract_vec(peers.to_vec(), rm);
        peers.push(args.entry.clone()); // add entry node

        // broadcast address to peers
        println!("[+] SYNC - broadcasting address");
        rm = broadcast(&peers, 0, &format!("{{\"addr\":\"{}\"}}", addr));

        // remove unreachable peers & update peers
        *peers = subtract_vec(peers.to_vec(), rm);
        println!("[+] SYNC - update list of peers successful");
    }

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

            // load json from buffer
            let data: RequestReceiver = match serde_json::from_str(&buffer) {
                Ok(n) => n,
                Err(e) => {
                    respond_code(&stream, 1);
                    eprintln!("[#] LISTENER - receive data error: {}", e);
                    return;
                }
            };

            // add peer
            if data.dtype == 0 {
                // get option of data
                let data_opt = data.data.get("addr");

                // if address is not none
                let peer = if !data_opt.is_none() {
                    data_opt.unwrap().to_string().replace("\"", "")

                // otherwise break
                } else {
                    respond_code(&stream, 1);
                    eprintln!("[#] DTYPE:0 - received none value");
                    return;
                };

                // check address
                if !check_addr(&peer) {
                    respond_code(&stream, 1);
                    eprintln!("[#] DTYPE:0 - address invalid");
                    return;
                }

                // add peer to list if not already contained
                let mut peers = peers.lock().unwrap();
                if !peers.contains(&peer) {
                    peers.push(peer);
                    respond_code(&stream, 0);

                // if already in list
                } else {
                    respond_code(&stream, 0);
                }

            // get peers
            } else if data.dtype == 1 {
                // respond list of peers
                respond_json(&stream, json!(*peers.lock().unwrap()));

            // add Transaction
            } else if data.dtype == 2 {
                // construct transaction
                let mut transaction = match Transaction::from_json(&data.data) {
                    Ok(n) => n,
                    Err(e) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:2 - construction failed: {:?}", e);
                        return;
                    }
                };

                // perform some checks on the transaction
                match transaction.validate() {
                    Ok(_) => {}
                    Err(e) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:2 - transaction invalid: {:?}", e);
                        return;
                    }
                }

                // distribute transaction to all nodes
                let mut peers = peers.lock().unwrap();
                if transaction.broadcast {
                    // overwrite transaction and parse into json string
                    transaction.broadcast = false; // disable broadcast
                    let transaction = transaction.as_json().to_string(); // serialize transaction

                    // broadcast peers
                    let failed = broadcast(&peers, 2, &transaction);

                    // remove unreachable peers
                    *peers = subtract_vec(peers.to_vec(), failed);
                }

                // add transaction to pool
                let mut pool = transactionpool.lock().unwrap();
                match pool.add(&transaction) {
                    Ok(_) => {
                        println!("[+] DTYPE:2 - transaction added\n\n{}", transaction.str());
                        respond_code(&stream, 0);
                    }
                    Err(e) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:2 - transaction not added: {:?}", e);
                        return;
                    }
                }

            // get transaction pool
            } else if data.dtype == 3 {
                // respend transaction pool
                respond_json(&stream, json!(*transactionpool.lock().unwrap().pool));

            // validate block
            } else if data.dtype == 4 {
                // construct block
                let block = match Block::from_json(&data.data) {
                    Ok(n) => n,
                    Err(_) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:4 - Block::from_json() failed");
                        return;
                    }
                };

                {
                    // debug
                    println!("\n\nReceived:\n{}\n", block.str());
                    println!(
                        "\n\nCurrent:\n{}\n",
                        mine_controller.current_block.lock().unwrap().str()
                    );
                }

                // parse hash difficulty
                let val = match BigUint::parse_bytes(block.hash.as_bytes(), 16) {
                    Some(n) => n,
                    None => {
                        respond_code(&stream, 3);
                        eprintln!("[#] DTYPE:4 - parse hash value error");
                        return;
                    }
                };
                {
                    // check hash difficulty
                    if val > get_difficulty(*difficulty.lock().unwrap()) {
                        respond_code(&stream, 3);
                        eprintln!("[#] DTYPE:4 - invalid hash difficulty");
                        return;
                    }
                }

                // check block
                match block.validate() {
                    Ok(_) => println!("[+] DTYPE:4 - block valid"),
                    Err(e) => {
                        respond_code(&stream, 3);
                        eprintln!("[#] DTYPE:4 - block invalid: {:?}", e);
                        return;
                    }
                }
                {
                    // check if block matches currently mined block
                    if block != *mine_controller.current_block.lock().unwrap() {
                        respond_code(&stream, 3);
                        eprintln!("[#] DTYPE:4 - block doesn't match currently mined block");
                        return;
                    }
                }

                // add block to chain
                match blockchain.lock().unwrap().add_block(&block) {
                    Ok(_) => {
                        mine_controller.skip(); // skip currently mined block
                        println!("[+] DTYPE:4 - add block to chain succeed");
                        respond_code(&stream, 2);
                    }
                    Err(e) => {
                        eprintln!("[#] DTYPE:4 - add block to chain error: {:?}", e);
                        respond_code(&stream, 3);
                    }
                }

            // request blockchain
            } else if data.dtype == 5 {
                // respond blockchain
                let chain = blockchain.lock().unwrap(); // lock blockchain
                let blocks: Vec<serde_json::Value> =
                    chain.get_chain().iter().map(|x| x.as_json()).collect(); // convert blocks to json
                respond_json(&stream, json!(blocks)); // respond blockchain
                return;
            }
        });
    }
}

// NOW:
//  - other todos in the code

// TODO: check if chain is still valid sometimes (every 10 blocks when the time was measured and
// the difficulty was adjusted)
// TODO: add pool feature where nodes have ID's to mine more efficiently
// TODO: add Docs to functions
// TODO: improve returning errors by using Result<val, Error> instead of Result<val, ()>
// TODO: improve logging
// TODO: remove everyhthing with //debug comment
// TODO: cleanup imports
// TODO: remove warnings by cargo
// TODO: real signatures and real wallet addresses
// TODO: multi signatures
// Resource: https://medium.com/learning-lab/how-cryptocurrencies-work-technical-guide-95950c002b8f
//
// TODO: in far future:
// - the miner should be run as release? (so the command might not be optimal)
//
// TODO: Optional:
// - encrypt traffic between nodes?
// - save blockchain to continue later?
