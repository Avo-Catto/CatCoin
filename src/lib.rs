use std::{env, error::Error, fmt::format, io::{Read, Write}, net::{Shutdown, TcpStream}, panic::catch_unwind, process::{Child, Command}, str::FromStr, vec};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use chrono::Utc;
use regex::Regex;
use std::any::Any;

#[derive(Debug)]
pub enum PoolError {
    DuplicatedTransaction,
}

#[derive(Debug)]
pub enum BlockChainError {
    BlockAlreadyInChain,
    InvalidIndex
}

#[derive(Debug)]
pub enum TransactionValidationError {
    MismatchSource,
    MismatchDestination,
    MismatchDate,
    MismatchHash,
}
type TVE = TransactionValidationError;

#[derive(Debug)]
pub enum BlockError {
    MismatchDate,
    TransactionValidationFailed,
    MismatchPreviousHash,
    MismatchHash,
    MismatchMerkleHash,
}

pub fn datetime_now() -> String {
    Utc::now().to_rfc3339()
}

pub fn hash_str(data: &[u8]) -> String {
    // hash data
    format!("{:x}", Sha256::digest(data))
}

pub fn merkle_hash(data: Vec<String>) -> Result<String, ()> {
    // check if length of list is even
    let len = data.len() - 1;
    let even: bool = match len % 2 {
        1 => true,
        0 => false,
        _ => false, // this will never happen
    };

    // merge hash
    let mut output: Vec<String> = Vec::new();
    let mut hash_input: String;
    let mut hash: String;

    for i in (0..len).step_by(2) {
        hash_input = format!("{}${}", data[i], data[i+1]); // merge two elements
        hash = hash_str(hash_input.as_bytes()); // hash it
        output.push(hash);
    }

    if !even { // append hash of last element if not even
        hash = hash_str(data[len].as_bytes());
        output.push(hash);
    }

    if len > 1 { merkle_hash(output) } // if elements left
    else if output.len() == 1 { Ok(output[0].clone()) } // return output
    else { Err(()) } // raise error
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub src: String,
    pub dst: String,
    pub date: String,
    pub val: f64,
    pub broadcast: bool,
    pub hash: String,
}

impl Transaction {
    // contstructor
    pub fn new(src: &str, dst: &str, val: f64, broadcast: bool) -> Transaction{
        let date = datetime_now();
        let hash_fmt = format!("{}${}${}${}", src, dst, date, val); 
        
        // construct transaction
        Transaction {
            src: String::from_str(src).unwrap(),
            dst: String::from_str(dst).unwrap(),
            date,
            val,
            broadcast,
            hash: hash_str(hash_fmt.as_bytes())
        }
    }

    pub fn from_json(json: &serde_json::Value) -> Result<Transaction, Box<dyn Any + Send>> {
        // construct transaction from json
        let transaction = catch_unwind(|| {
            let mut transaction = Self::new(
                json.get("src").unwrap().as_str().expect("Transaction::from_json: src"),
                json.get("dst").unwrap().as_str().expect("Transaction::from_json: dst"),
                json.get("val").unwrap().as_f64().expect("Transaction::from_json: val"),
                json.get("broadcast").unwrap().as_bool().expect("Transaction::from_json: broadcast")
            );
            transaction.date = json.get("date").unwrap().to_string().replace("\"", "");
            transaction.hash = json.get("hash").unwrap().to_string().replace("\"", "");
            transaction
        });
        transaction
    }

    pub fn as_json(&self) -> serde_json::Value {
        // return transaction as json
        json!({
            "src": self.src,
            "dst": self.dst,
            "date": self.date,
            "val": self.val,
            "broadcast": self.broadcast,
            "hash": self.hash,
        })
    }

    pub fn recalc_hash(&self) -> String {
        // recalculate hash and return it
        let hash_fmt = format!("{}${}${}${}", self.src, self.dst, self.date, self.val);
        hash_str(hash_fmt.as_bytes())
    }

    pub fn validate(&self) -> Result<(), TVE> {
        // check if values of transaction are valid
        let uuid_re = Regex::new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").unwrap();
        let datetime_re = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\d{3}\+\d{2}:\d{2})$").unwrap();
        
        // regex check
        if !uuid_re.is_match(&self.src) { return Err(TVE::MismatchSource) } // checksrc
        if !uuid_re.is_match(&self.dst) { return Err(TVE::MismatchDestination) } // check dst
        if !datetime_re.is_match(&self.date) { return Err(TVE::MismatchDate) } // check date
        if self.recalc_hash() != self.hash { return Err(TVE::MismatchHash) } // check hash
        Ok(())
    }

    pub fn str(&self) -> String {
        // return transaction as String
        format!(
            "- Source: {}\n- Destination: {}\n- Date: {}\n- Value: {}\n- Hash: {}\n", 
            self.src, self.dst, self.date, self.val, self.hash
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TransactionPool {
    pub pool: Vec<Transaction>,
}

impl TransactionPool {
    // constructor
    pub fn new() -> TransactionPool {
        TransactionPool { pool: Vec::new() }
    }

    pub fn add(&mut self, transaction: &Transaction) -> Result<(), PoolError> {
        // check if transaction already in pool
        if self.pool.contains(transaction) {
            return Err(PoolError::DuplicatedTransaction);
        }
        self.pool.push(transaction.clone()); // add transaction to pool
        Ok(())
    }

    pub fn flush(&mut self) {
        self.pool.clear();
    }

    pub fn from_vec(vector: &Vec<Transaction>) -> TransactionPool {
        // create transaction pool from vector
        let mut pool = Self::new();
        pool.pool = vector.clone();
        pool
    }

    pub fn str(&self) -> String {
        // create vector with capacity of count of transactions
        let lenght = self.pool.len();
        let mut output: Vec<String> = Vec::with_capacity(lenght);

        // push all stringified transactions to vector
        for transaction in &self.pool {
            output.push(transaction.str());
        }
        output.join("\n") // return list of transactions as one String
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct Block {
    pub index: u64,
    pub datetime: String,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub nonce: u64,
    pub hash: String,
    merkle: String,
    hash_str: String,
}

impl Block {
    // constructor
    pub fn new(index: u64, transactions: Vec<Transaction>, prev_hash: String) -> Block {
        // get datetime and calculate merkle hash
        let datetime = datetime_now();
        let merkle: String = match transactions.is_empty() {
            true => { String::new() }
            false => {
                merkle_hash(transactions.iter().map(|x| x.hash.clone()).collect())
                .expect("Block::new().merkle_hash failed")
            }
        };
        Block {
            index,
            datetime: datetime.clone(),
            transactions,
            previous_hash: prev_hash,
            nonce: 0,
            hash: String::new(),
            merkle: merkle.clone(),
            hash_str: format!("{}${}${}", index, datetime, merkle),
        }
    }

    pub fn calc_hash(&mut self, nonce:u64) -> String {
        // update nonce and calculate hash
        self.nonce = nonce;
        let hash = hash_str(format!("{}${}", self.hash_str, nonce).as_bytes());
        self.hash = hash.clone();
        hash
    }

    pub fn validate(&self) -> Result<(), BlockError> { // TODO: add / check hash difficulty
        // check if values of block are valid
        let sha256_re = Regex::new("^[a-fA-F0-9]{64}$").unwrap();
        let datetime_re = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\d{3}\+\d{2}:\d{2})$").unwrap();
        
        // regex checks
        if !sha256_re.is_match(&self.previous_hash) { return Err(BlockError::MismatchPreviousHash) } // check previous hash
        if !datetime_re.is_match(&self.datetime) { return Err(BlockError::MismatchDate) } // check date
        if self.clone().calc_hash(self.nonce) != self.hash { return Err(BlockError::MismatchHash) } // check hash

        // check transactions
        for t in &self.transactions {
            match t.validate() {
                Ok(()) => continue,
                Err(e) => {
                    println!("transaction invalid: {:?}", e);
                    return Err(BlockError::TransactionValidationFailed);
                },
            }
        }

        // recreate merkle hash to validate
        let merkle = match self.transactions.is_empty() {
            true => { String::new() }
            false => {
                merkle_hash(self.transactions.iter().map(|x| x.hash.clone()).collect())
                .expect("Block::validate().merkle_hash failed")
            }
        };
        if merkle != self.merkle { return Err(BlockError::MismatchMerkleHash) } // check merkle hash
        Ok(())
    }

    pub fn as_json(&self) -> serde_json::Value{
        // return block as json
        json!({
            "index": self.index,
            "datetime": self.datetime,
            "transactions": self.transactions.iter().map(|x| x.as_json()).collect::<Vec<serde_json::Value>>(),
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "merkle": self.merkle,
        })
    }

    pub fn from_json(json: &serde_json::Value) -> Result<Block, Box<dyn Any + Send>> {
        // deserialize transactions
        let json = json.clone();
        let mut transactions: Vec<Transaction> = Vec::new();
        let data = json.get("transactions");

        // iterate through transactions
        if data.is_some() {
            for t in data.unwrap().as_array().unwrap() {
                // construct transactions
                match Transaction::from_json(t) {
                    Ok(n) => transactions.push(n),
                    Err(e) => return Err(Box::new(e)),
                };
            }
        }

        // construct block
        let mut block = Self::new(
            json.get("index").unwrap().as_u64().expect("Block::from_json: index"),
            transactions, 
            json.get("previous_hash").unwrap().to_string().replace("\"", ""),
        );

        // update values
        block.datetime = json.get("datetime").unwrap().to_string().replace("\"", "");
        block.nonce = json.get("nonce").unwrap().as_u64().expect("Block::from_json: nonce");
        block.hash = json.get("hash").unwrap().to_string().replace("\"", "");
        block.merkle = json.get("merkle").unwrap().to_string().replace("\"", "");
        block.hash_str = format!("{}${}${}", block.index, block.datetime, block.merkle);
        Ok(block)
    }

    pub fn str(&self) -> String {
        // block head
        let mut output: String = format!(
            "> Index: {}\n> Datetime: {}\n> Previous Hash: {}\n> Nonce: {}\n> Hash: {}\n> Transactions:\n", 
            self.index, self.datetime, self.previous_hash, self.nonce, self.hash
        );

        // append transactions
        for t in &self.transactions {
            output = format!("{}\n{}", output, t.str());
        }
        output
    }
}

#[derive(Clone)]
pub struct BlockChain {
    chain: Vec<Block>,
}

impl BlockChain {
    // constructor
    pub fn new() -> BlockChain {
        BlockChain {
            chain: Vec::new(),
        }
    }

    // construct blockchain with genisis block
    pub fn new_with_genisis() -> BlockChain {
        let mut chain = Self::new(); // new chain
        let mut genisis_block = Block::new(0, Vec::new(), String::new()); // new block
        genisis_block.calc_hash(0); // calc hash of block
        let _ = chain.add_block(&genisis_block); // append block to chain
        chain
    }

    pub fn get_chain(&self) -> Vec<Block> {
        self.chain.clone()
    }

    pub fn set_chain(&mut self, chain: Vec<Block>) {
        self.chain = chain;
    }

    pub fn get_latest(&self) -> Result<Block, ()> {
        // check if none
        let latest = self.chain.last();
        if latest.is_none() { Err(()) }
        else { Ok(latest.unwrap().clone()) }
    }

    pub fn add_block(&mut self, block: &Block) -> Result<(), BlockChainError> {
        // add block to chain
        // check if block already in chain
        if self.chain.contains(block) {
            return Err(BlockChainError::BlockAlreadyInChain)
        }

        // check index
        match self.chain.last() {
            Some(n) => if n.index + 1 != block.index { return Err(BlockChainError::InvalidIndex) },
            None => if block.index != 0 { return Err(BlockChainError::InvalidIndex) },
        }
        self.chain.push(block.clone()); // add block to chain
        Ok(())
    }

    pub fn str(&self) -> String {
        let mut output = String::new();
        for block in &self.chain {
            output = format!("{}\n{}", output, block.str());
        }
        output
    }
}

pub struct MineController {
    cmd: &'static str,
    start: u64,
    steps: u64,
    difficulty: u8,
    block: Block,
}

impl MineController {
    // constructor
    pub fn new(start: u64, steps: u64, difficulty: u8, block: Block) -> MineController {
        MineController { cmd: "cargo", start, steps, difficulty, block }
    }

    pub fn run(&self) -> Result<[String; 2], std::io::Error> {
        // format data
        let plain = format!(
            "{{\"start\":{},\"steps\":{},\"difficulty\":{},\"block\":{}}}", 
            self.start, self.steps, self.difficulty, self.block.as_json()
        );

        // run child proccess
        match Command::new(self.cmd).args([
            "run", "--bin", "miner", "--", &STANDARD.encode(plain),
        ]).output() {
            Ok(n) => {
                let stdout = String::from_utf8(n.stdout).unwrap();
                let stderr = String::from_utf8(n.stderr).unwrap();
                return Ok([stdout, stderr])
            },
            Err(e) => Err(e),
        }
    }
}

pub fn get_difficulty(difficulty: u8) -> BigUint {
    // get hash difficulty
    let pat = "F".repeat(usize::from(difficulty));
    let to = "0".repeat(usize::from(difficulty));
    let hex_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".replacen(&pat, &to, 1);
    BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap()
}

pub fn check_addr(addr: &String) -> bool {
    // check peer address; for example "127.0.0.1:8080"
    let addr_re = Regex::new(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})$"
    ).unwrap();
    addr_re.is_match(addr)
}

pub fn respond_code(mut stream: &TcpStream, code: i8) {
    // respond code
    stream.write(format!("{{\"res\": {code}}}").as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
}

pub fn respond_json(mut stream: &TcpStream, json: serde_json::Value) {
    // respond json
    stream.write(format!("{{\"res\": 0, \"data\": {data}}}", data=json.to_string()).as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
}

pub fn send_string(mut stream: &TcpStream, data: String) -> Result<String, Box<dyn Error>> {
    // write data to stream
    match stream.write(data.as_bytes()) {
        Ok(_) => {},
        Err(e) => return Err(Box::new(e)),
    }

    // send EOF
    match stream.shutdown(Shutdown::Write) {
        Ok(_) => {},
        Err(e) => return Err(Box::new(e)),
    }
    
    // read response
    let mut buffer = String::new();
    match stream.read_to_string(&mut buffer) {
        Ok(_) => return Ok(buffer),
        Err(e) => return Err(Box::new(e)),
    }
}

pub fn broadcast(peers: &Vec<String>, dtype: i8, data: &String) -> Vec<String> {
    // broadcast data to all nodes and return list of nodes where connection failed
    let mut peers_failed: Vec<String> = Vec::new();
    for peer in peers {
        // connect to peer
        let stream = match TcpStream::connect(peer) {
            Ok(n) => n,
            Err(_) => {
                peers_failed.push(peer.clone());
                continue;
            }
        };

        // send transaction to peer
        match send_string(&stream, format!("{{\"dtype\": {}, \"data\": {}}}", dtype, data)) {
            Ok(_) => {},
            Err(_) => {
                peers_failed.push(peer.clone());
                continue;
            }
        };
    }
    peers_failed
}

pub fn subtract_vec<T: PartialEq>(mut x: Vec<T>, y: Vec<T>) -> Vec<T>{
    for i in y {
        match x.iter().position(|y| y == &i) {
            Some(n) => x.remove(n),
            None => continue,
        };
    }
    x
}