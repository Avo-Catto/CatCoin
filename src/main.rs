// use crate::src::{merkle_hash, Block, BlockChain, Transaction, TransactionPool};
use src::BlockChain;
use std::{borrow::{Borrow, BorrowMut}, io::{Read, Write}, net::{Shutdown, TcpListener}, sync::{Arc, Mutex}, thread};
use serde::Deserialize;
use serde_json::json;
use clap::Parser;
use uuid::Uuid;
use crate::src::{Block, Transaction, TransactionPool, hash_str};

mod src;
mod errors;

#[derive(Deserialize, Debug)]
struct Receiver {
    dtype: i8,
    data: serde_json::Value
}

enum ReceivedValue {
    TransactionVal(Transaction),
    BlockVal(Block),
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
}

fn main() {
    // get args
    let args = Args::parse();
    println!("{:#?}", args);

    // construct transactionpool and blockchain as mutex
    let mut transactionpool = TransactionPool::new();
    let mut blockchain = match args.genisis {
        true => BlockChain::new_with_genisis(),
        false => BlockChain::new(),
    };

    // format address
    let addr = format!("{}:{}", args.ip, args.port);
    println!("listening on: {}", addr);

    // create listener
    let listener: TcpListener = TcpListener::bind(addr).unwrap();
    for stream in listener.incoming() {

        // manage output
        let output: Arc<Mutex<Result<ReceivedValue, ()>>> = Arc::new(Err(()).into());
        let output_clone = Arc::clone(&output);

        // spawn thread and handle connection
        let res = thread::spawn(move || {
            // overwriting stream
            let mut stream = stream.unwrap();

            // create buffer and receive data
            let mut buffer = String::new();
            stream.read_to_string(&mut buffer).unwrap();
            stream.shutdown(Shutdown::Read).unwrap();

            println!("{}", buffer); // DEBUG

            // load json from buffer
            let data: Receiver = match serde_json::from_str(&buffer) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("# receiving of data failed: {}", e);
                    Receiver { dtype: -1, data: json!({}) }
                },
            };

            // send response
            stream.write(format!("{{\"res\": {t} }}", t=data.dtype).as_bytes()).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();

            // output
            let mut out = output_clone.lock().unwrap();

            // add Transaction
            if data.dtype == 1 {
                // construct transaction
                let transaction = Transaction::from_json(data.data);
                
                // perform some checks on the transaction
                match transaction.validate() {
                    Ok(()) => println!("# transaction valid"),
                    Err(e) => {
                        eprintln!("# transaction invalid: {:?}", e);
                    },
                }

                // set transaction as output
                *out = Ok(ReceivedValue::TransactionVal(transaction));
            
            // add Block
            } else if data.dtype == 2 {
                // construct block
                let block = Block::from_json(data.data);
                
                // perform some checks on block
                match block.validate() {
                    Ok(()) => println!("# block valid"),
                    Err(e) => {
                        eprintln!("# block invalid: {:?}", e);
                        return
                    },
                }

                // set block as output
                *out = Ok(ReceivedValue::BlockVal(block));
            } else { *out = Err(()) }

            // drop output
            drop(out);
        });

        res.join().unwrap();

        // add transaction / block to pool / chain
        match output.lock().unwrap().as_ref() {
            Ok(n) => {
                match n {
                    // add transaction to pool
                    ReceivedValue::TransactionVal(n) => {
                        match transactionpool.add(&n) {
                            Ok(_) => println!("# transaction added"),
                            Err(e) => eprintln!("# transaction not added because of: {:?}", e),
                        }
                    },

                    // add block to chain
                    ReceivedValue::BlockVal(n) => {
                        match blockchain.add_block(&n) {
                            Ok(_) => println!("# block added"),
                            Err(e) => eprintln!("# block not added because of: {:?}", e),
                        }
                    },
                }
            },
        Err(_) => eprintln!("# nothing was added"),
        };

        // debug
        println!("Transactions: \n{}", transactionpool.str());
        println!("Blockchain: {}\n\n\n", blockchain.str());

    };

}

// TODO: implement multi threading (look at how multithreaded web sockets are made in rust)
// TODO: implement database for a list of peers
// TODO: add dtype 3 for receiving messages to add/get peers with distribute option
// TODO: make it more Bitcoin like -> https://developer.bitcoin.org/devguide/index.html
// TODO: improve logging