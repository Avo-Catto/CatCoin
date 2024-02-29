use std::str::FromStr;
use serde_json::json;
use sha2::{Sha256, Digest};

pub fn hash_str(data: &[u8]) -> String {
    // hash data
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:X}", hasher.finalize()) // return hex value as String
}

pub fn merkle_hash(data: Vec<String>) -> Result<String, ()> {
    // take a list of strings and hash it to one by using the merkle tree TODO: doc strings!!!

    // check if length of list is even
    let len = data.len() - 1;
    let even: bool = match len % 2 {
        1 => true,
        0 => false,
        _ => false, // this case will never happen
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

    if !even {
        hash = hash_str(data[len].as_bytes());
        output.push(hash);
    }

    if len > 1 { merkle_hash(output) }
    else if output.len() == 1 { Ok(output[0].clone()) }
    else { Err(()) }
}

#[derive(Clone)]
pub struct Transaction {
    src: String,
    dst: String,
    date: String,
    val: f64,
    broadcast: bool,
    hash: String
}

impl Transaction {
    // contstructor
    pub fn new(src: &str, dst: &str, date: &str, val: f64, broadcast: bool) -> Transaction{
        let hash_fmt: String = format!("{}${}${}${}", src, dst, date, val); // create hash format string
        // construct transaction
        Transaction {
            src: String::from_str(src).unwrap(),
            dst: String::from_str(dst).unwrap(),
            date: String::from_str(date).unwrap(),
            val,
            broadcast,
            hash: hash_str(hash_fmt.as_bytes())
        }
    }

    pub fn from_json(json: serde_json::Value) -> Transaction {
        // construct transaction from json
        Self::new(
            json.get("src").unwrap().as_str().expect("from_json: src"),
            json.get("dst").unwrap().as_str().expect("from_json: dst"),
            json.get("date").unwrap().as_str().expect("from_json: date"),
            json.get("val").unwrap().as_f64().expect("from_json: val"),
            json.get("broadcast").unwrap().as_bool().expect("from_json: broadcast")
        )
    }

    pub fn as_json(&self) -> serde_json::Value {
        // return transaction as json
        json!({
            "src": self.src,
            "dst": self.dst,
            "date": self.date,
            "val": self.val,
            "broadcast": self.broadcast
        })
    }

    pub fn str(&self) -> String {
        // return transaction as String
        format!(
            "> Source: {}\n> Destination: {}\n> Date: {}\n> Value: {}\n> Hash: {}", 
            self.src, self.dst, self.date, self.val, self.hash
        )
    }
}

pub struct TransactionPool {
    pool: Vec<Transaction>
}

impl TransactionPool {
    // constructor
    pub fn new() -> TransactionPool {
        TransactionPool { pool: Vec::new() }
    }

    pub fn add(&mut self, transaction: &Transaction) -> bool { // TODO: return error or ok
        // check if transaction already in pool
        for iter_transaction in &self.pool {
            if iter_transaction.hash == transaction.hash { return false } 
        }
        self.pool.push(transaction.clone()); // add transaction to pool
        true
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
