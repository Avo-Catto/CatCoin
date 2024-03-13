use std::{str::FromStr, error::Error};
use serde_json::json;
use sha2::{Digest, Sha256};
use chrono::Utc;
use regex::Regex;
use crate::errors::{BlockChainError, PoolError, BlockError, TransactionValidationError as TVE};

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

#[derive(Clone, PartialEq, Debug)]
pub struct Transaction {
    src: String,
    dst: String,
    date: String,
    val: f64,
    pub broadcast: bool,
    hash: String,
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

    pub fn from_json(json: &serde_json::Value) -> Result<Transaction, ()> { // TODO: error handling
        // construct transaction from json
        let mut transaction = Self::new(
            json.get("src").unwrap().as_str().expect("Transaction::from_json: src"),
            json.get("dst").unwrap().as_str().expect("Transaction::from_json: dst"),
            json.get("val").unwrap().as_f64().expect("Transaction::from_json: val"),
            json.get("broadcast").unwrap().as_bool().expect("Transaction::from_json: broadcast")
        );
        transaction.date = json.get("date").unwrap().to_string().replace("\"", "");
        transaction.hash = json.get("hash").unwrap().to_string().replace("\"", "");
        Ok(transaction)
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

    pub fn validate(&self) -> Result<(), TVE> { // TODO: refactor regex checks using "is_match"
        // check if values of transaction are valid
        let uuid_re = Regex::new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").unwrap();
        let datetime_re = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\d{3}\+\d{2}:\d{2})$").unwrap();
        
        // regex check
        if uuid_re.captures(&self.src).is_none() { return Err(TVE::MismatchSource) } // check src
        if uuid_re.captures(&self.dst).is_none() { return Err(TVE::MismatchDestination) } // check dst
        if datetime_re.captures(&self.date).is_none() { return Err(TVE::MismatchDate) } // check date
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

pub struct TransactionPool {
    pool: Vec<Transaction>,
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

    pub fn str(&self) -> String {
        // create vector with capacity of count of transactions
        let lenght = self.pool.len();
        let mut output: Vec<String> = Vec::with_capacity(lenght);

        // push all stringified transactions to vector
        for transaction in &self.pool {
            output.push(transaction.str());
        }
        output.join("\n\n") // return list of transactions as one String
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Block {
    pub index: u64,
    datetime: String,
    transactions: Vec<Transaction>,
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

    // TODO: refactor regex checks using "is_match"
    pub fn validate(&self) -> Result<(), BlockError> { // TODO: add / check hash difficulty
        // check if values of block are valid
        let sha256_re = Regex::new("^[a-fA-F0-9]{64}$").unwrap();
        let datetime_re = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\d{3}\+\d{2}:\d{2})$").unwrap();
        
        // regex checks
        if sha256_re.captures(&self.previous_hash).is_none() { return Err(BlockError::MismatchPreviousHash) } // check previous hash
        if datetime_re.captures(&self.datetime).is_none() { return Err(BlockError::MismatchDate) } // check date
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

    pub fn from_json(json: &serde_json::Value) -> Result<Block, ()> { // TODO: improve error return
        // deserialize transactions
        let json = json.clone();

        println!("hash: {:#?}", json); //debug
        println!("index: {:?}", json.get("index")); //debug

        let mut transactions: Vec<Transaction> = Vec::new();
        let data = json.get("transactions");

        // iterate through transactions
        if data.is_some() {
            for t in data.unwrap().as_array().unwrap() {
                // construct transactions
                match Transaction::from_json(t) {
                    Ok(n) => transactions.push(n),
                    Err(_) => break,
                };
            }

            // check if transaction construction failed
            if transactions.len() < data.unwrap().as_array().unwrap().len() {
                return Err(());
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
