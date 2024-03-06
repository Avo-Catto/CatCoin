// use crate::src::{merkle_hash, Block, BlockChain, Transaction, TransactionPool};
use src::BlockChain;
use std::{io::{Read, Write}, net::{TcpListener, Shutdown}, thread, sync::Mutex};
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

    // # transaction
    // println!("{:?}", Transaction::new(&Uuid::new_v4().to_string(), &Uuid::new_v4().to_string(), 0.4, false).as_json().to_string());
    // println!("{:?}", Transaction::new(&Uuid::new_v4().to_string(), &Uuid::new_v4().to_string(), 0.8, false).as_json().to_string());
    
    // # block
    let transactions_test = [Transaction::new(&Uuid::new_v4().to_string(), &Uuid::new_v4().to_string(), 0.4, false), Transaction::new(&Uuid::new_v4().to_string(), &Uuid::new_v4().to_string(), 0.8, false)];
    let mut block = Block::new(0, transactions_test.to_vec(), hash_str("avocado".as_bytes()));
    block.calc_hash(2);
    println!("{:?}", block.as_json().to_string());


    // get args
    let args = Args::parse();
    println!("{:#?}", args);

    /*
    let mut blockchain = match args.genisis {
        true => Mutex::new(BlockChain::new_with_genisis()),
        false => Mutex::new(BlockChain::new()),
    };
    */
    let mut transactionpool = TransactionPool::new();
    let mut blockchain = match args.genisis {
        true => BlockChain::new_with_genisis(),
        false => BlockChain::new(),
    };

    // #### Communication ####
    // format address
    let addr = format!("{}:{}", args.ip, args.port);
    println!("listening on: {}", addr);

    // create listener
    let listener: TcpListener = TcpListener::bind(addr).unwrap();
    for stream in listener.incoming() {
        // thread::spawn(move || { // spawn thread and handle connection

            // overwriting stream
            let mut stream = stream.unwrap();

            // create buffer and receive data
            let mut buffer = String::new();
            stream.read_to_string(&mut buffer).unwrap();
            stream.shutdown(Shutdown::Read).unwrap();

            println!("{}", buffer);

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

            // add Transaction
            if data.dtype == 1 {
                // construct transaction
                let transaction = Transaction::from_json(data.data);
                
                // perform some checks on the transaction
                match transaction.validate() {
                    Ok(()) => println!("# transaction valid"),
                    Err(e) => {
                        eprintln!("# transaction invalid: {:?}", e);
                        continue
                    },
                }
                
                // add transaction to pool
                match transactionpool.add(&transaction) {
                    Ok(_) => println!("# transaction added"),
                    Err(e) => eprintln!("# transaction not added because of: {:?}", e),
                }
            
            // add Block
            } else if data.dtype == 2 {
                // construct block
                let block = Block::from_json(data.data);
                
                // perform some checks on block
                match block.validate() {
                    Ok(()) => println!("# block valid"),
                    Err(e) => {
                        eprintln!("# block invalid: {:?}", e);
                        continue
                    },
                }

                match blockchain.add_block(&block) { // add block to chain FIXME: block added even already in chain
                    Ok(_) => println!("# block added"),
                    Err(e) => eprintln!("# block not added because of: {:?}", e),
                }
                // blockchain.lock();
                // blockchain.get_mut().unwrap().add_block(&block).expect("received block couldN't be appended to blockchain");
            }

            // debug
            println!("Transactions: \n{}", transactionpool.str());
            println!("Blockchain: {}\n\n\n", blockchain.str());
        // });
    }
}
