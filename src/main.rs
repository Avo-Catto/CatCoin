use src::BlockChain;
use std::{borrow::Borrow, fmt::format, io::{Read, Write}, net::{Shutdown, TcpListener, TcpStream}, panic::catch_unwind, sync::{Arc, Mutex}, thread};
use serde::Deserialize;
use serde_json::json;
use clap::{builder::Str, Parser};
use regex::Regex;
use crate::src::{Block, Transaction, TransactionPool};
use std::error::Error;
use std::process::exit;

mod src;
mod errors;

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
    entry: String
}

fn check_addr(addr: &String) -> bool {
    // check peer address; for example "127.0.0.1:8080"
    let addr_re = Regex::new(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})$"
    ).unwrap();
    addr_re.is_match(addr)
}

fn respond_code(mut stream: &TcpStream, code: i8) {
    // respond code
    stream.write(format!("{{\"res\": {code}}}").as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
}

fn respond_json(mut stream: &TcpStream, json: serde_json::Value) {
    // respond json
    stream.write(format!("{{\"res\": 0, \"data\": {data}}}", data=json.to_string()).as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
}

fn send_string(mut stream: &TcpStream, data: String) -> String {
    // send data to other node
    stream.write(data.as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();

    // read response
    let mut buffer = String::new();
    stream.read_to_string(&mut buffer).unwrap();
    buffer
}

fn get_chain(addr: &String) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    // connect to node
    let stream = match TcpStream::connect(addr) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] get-chain() - error: {}", e);
            return Err(Box::new(e));
        }
    };

    let buffer = send_string(&stream, "{\"dtype\":4, \"data\":{}}".to_string());

    // load json from buffer
    let data: ResponseReceiver = match serde_json::from_str(&buffer) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] get-chain() - error: {}", e);
            return Err(Box::new(e));
        },
    };
    Ok(vec![data.data])
}

fn main() {
    // get args
    let args = Args::parse();

    // debug
    println!("{:#?}", args);
    let mut counter: u8 = 0;

    // construct mutex objects
    let peers = Arc::new(Mutex::new(Vec::<String>::new()));
    let transactionpool = Arc::new(Mutex::new(TransactionPool::new()));
    let blockchain = match args.genisis {
        true => Arc::new(Mutex::new(BlockChain::new_with_genisis())),
        false => Arc::new(Mutex::new(BlockChain::new())),
    };

    // get blockchain from another node
    if !args.genisis && check_addr(&args.entry) {
        println!("[+] updating chain from node: {}", args.entry);
        
        // connect to node & receive blockchain
        match get_chain(&args.entry) {
            Ok(n) => {
                // deserialize blocks
                let mut chain: Vec<Block> = Vec::new();
                for i in n {
                    // construct block
                    match Block::from_json(&i[0]) {
                        Ok(n) => chain.push(n),
                        Err(_) => {
                            eprintln!("[#] failed parsing block");
                            exit(1);
                        },
                    };
                }
                // add blocks to chain
                let mut blockchain = blockchain.lock().unwrap();
                blockchain.set_chain(chain);
                drop(blockchain);
                println!("[+] blockchain updated successfully")
            },
            Err(e) => {
                panic!("[#] failed updating chain {}", e);
            }
        }
    } else if !args.genisis { // if no entry node specified
        eprintln!("[#] no entry node specified");
        exit(1);
    }

    // TODO: get peer list
    // TODO: send address to all peers

    // debug
    println!("Genisis Hash: {}", blockchain.lock().unwrap().get_latest().unwrap().hash);

    // format address
    let addr = format!("{}:{}", args.ip, args.port);
    println!("listening on: {}", addr);

    // create listener
    let listener: TcpListener = TcpListener::bind(addr).unwrap();
    for stream in listener.incoming() {
        // debug
        counter += 1;

        // clone mutex instances
        let peers = Arc::clone(&peers);
        let transactionpool = Arc::clone(&transactionpool);
        let blockchain = Arc::clone(&blockchain);

        // spawn thread and handle connection
        let t = thread::spawn( move || {
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
                    eprintln!("# receiving of data failed: {}", e);
                    return;
                },
            };

            println!("{:#?}", data.data.as_object()); // debug

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

                // add peer to list
                let mut peers = peers.lock().unwrap();
                peers.push(peer);
                respond_code(&stream, 0);
                drop(peers);
            
            // get peers
            }  else if data.dtype == 1 {
                // respend list of peers
                respond_json(&stream, json!(*peers.lock().unwrap()));

            // add Transaction
            } else if data.dtype == 2 {
                // construct transaction
                let transaction = match Transaction::from_json(&data.data) {
                    Ok(n) => n,
                    Err(_) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:0 - Transaction::from_json() failed");
                        return;
                    },
                };

                // perform some checks on the transaction
                match transaction.validate() {
                    Ok(_) => println!("[+] DTYPE:1 - transaction valid"),
                    Err(e) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:1 - transaction invalid: {:?}", e);
                        return;
                    },
                }

                // distribute transaction to all nodes
                let mut peers = peers.lock().unwrap();
                if transaction.broadcast {

                    // overwrite transaction and parse into json string
                    let mut transaction = transaction.clone();
                    transaction.broadcast = false; // disable broadcast
                    let transaction = transaction.as_json().to_string(); // serialize transaction

                    // iterate through peers and connect to them
                    for peer in peers.clone() {
                        let stream = match TcpStream::connect(peer.clone()) {
                            Ok(n) => n,
                            
                            // if connection fails get index and remove from list
                            Err(e) => {
                                let idx = peers.iter().position(|x| x == &peer).unwrap();
                                peers.remove(idx);
                                eprintln!("[#] DTYPE:1 - removed peer: {:?}", e);
                                continue;
                            }
                        };
                        // send transaction to peer
                        send_string(&stream, format!("{{\"dtype\": 1, \"data\": {t}}}", t=transaction));
                        println!("[+] DTYPE:1 - data sent");

                        println!("{}", buffer); // debug
                        println!("[+] DTYPE:1 - sent transaction to {}", peer);
                    }
                }

                // add transaction to pool
                let mut pool = transactionpool.lock().unwrap();
                match pool.add(&transaction) {
                    Ok(_) => {
                        // debug
                        println!("# transaction added");
                        println!("# pool:\n{}", pool.str());
                        respond_code(&stream, 0);
                        drop(pool);
                    },
                    Err(e) => {
                        respond_code(&stream, 1);
                        eprintln!("# transaction not added because of: {:?}", e);
                        return;
                    },
                }
            
            // validate block
            } else if data.dtype == 3 {
                // construct block
                let block = match Block::from_json(&data.data) {
                    Ok(n) => n,
                    Err(_) => {
                        respond_code(&stream, 1);
                        eprintln!("[#] DTYPE:2 - Block::from_json() failed");
                        return;
                    },
                };
                
                // check integrity in blockchain
                let chain = blockchain.lock().unwrap();
                match chain.get_latest() {
                    Ok(n) => {
                        // check index
                        if n.index + 1 != block.index {
                            respond_code(&stream, 3);
                            eprintln!("[+] DTYPE:2 - invalid index");
                            return;
                        }
                        // check previous hash
                        if n.hash != block.previous_hash {
                            respond_code(&stream, 3);
                            eprintln!("[+] DTYPE:2 - invalid previous hash");
                            return;
                        }
                    },
                    Err(_) => {
                        respond_code(&stream, 3);
                        return;
                    },
                }

                // check block
                match block.validate() {
                    Ok(_) => {
                        respond_code(&stream, 2);
                        println!("[+] DTYPE:2 - block valid");
                        return;
                    },
                    Err(e) => {
                        respond_code(&stream, 3);
                        eprintln!("[#] DTYPE:2 - block invalid: {:?}", e);
                        return;
                    }
                }
            
            // request blockchain
            } else if data.dtype == 4 {
                let chain = blockchain.lock().unwrap();
                let blocks: Vec<serde_json::Value> = chain.get_chain().iter().map(|x| x.as_json()).collect();
                respond_json(&stream, json!(blocks));
                return;

            // add Block
            } else if data.dtype == -1 {
                // construct block
                let mut block = match Block::from_json(&data.data) {
                    Ok(n) => n,
                    Err(_) => {
                        respond_code(&stream, 1);
                        return;
                    }
                };
                let mut chain = blockchain.lock().unwrap();
                
                // debug
                block.index = chain.get_latest().unwrap().index + 1;
                
                // perform some checks on block
                match block.validate() {
                    Ok(()) => println!("# block valid"),
                    Err(e) => {
                        eprintln!("# block invalid: {:?}", e);
                        return
                    },
                }

                //add block to chain // TODO: change it to make it update the blockchain than rather only receiving blocks and appending them
                match chain.add_block(&block) {
                    Ok(_) => {
                        println!("# block added");
                        println!("# chain: {}", chain.str()); // debug
                        drop(chain);
                    },
                    Err(e) => eprintln!("# block not added because of: {:?}", e),
                }
            }
        });
        
        // debug
        if counter >= 10 {
            t.join().unwrap();
            println!("break now!");
            break;
        }
    };

    // debug
    let transactionpool = transactionpool.lock().unwrap();
    println!("transactions:\n{}", transactionpool.str());
    let peers = peers.lock().unwrap();
    println!("peers: {:?}", peers)

}

// TODO: add "get blockchain" functionality to socket
// TODO: implement multi threading (look at how multithreaded web sockets are made in rust)
// TODO: implement database for a list of peers
// TODO: add dtype 3 for receiving messages to add/get peers with distribute option
// TODO: add mined block confirmation by other nodes
// TODO: make it more Bitcoin like -> https://developer.bitcoin.org/devguide/index.html
// TODO: improve returning errors by using Result<val, Error> instead of Result<val, ()>
// TODO: improve logging
// TODO: remove everyhthing with //debug comment
// TODO: save blockchain to continue later
// Resource: https://medium.com/learning-lab/how-cryptocurrencies-work-technical-guide-95950c002b8f