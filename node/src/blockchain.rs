extern crate base64;
extern crate rand;
use self::base64::{engine::general_purpose::STANDARD, Engine};
use self::rand::{prelude::SliceRandom, thread_rng, Rng};
use crate::share::DIFFICULTY;
use crate::{
    comm::*,
    share::{ADDR, ARGS, COINBASE, DB_HEAD_PATH, DB_POS_PATH, DB_TXS_PATH},
    utils::*,
};
use openssl::{error::ErrorStack, hash::MessageDigest, pkey::PKey, sign::Verifier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sled::{Db, IVec};
use std::process::ChildStderr;
use std::{
    any::Any,
    collections::HashMap,
    error::Error,
    io::{BufReader, BufWriter, Read, Write},
    panic::catch_unwind,
    process::{exit, Child, Command, Stdio},
    str::FromStr,
    sync::{mpsc, Arc, Mutex, TryLockError},
    thread,
    time::Duration,
    usize,
};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub nonce: u64,
    pub hash: String,
    pub merkle: String,
    pub hash_str: String,
}

impl Block {
    /// Constructor
    pub fn new(index: u64, transactions: Vec<Transaction>, prev_hash: String) -> Block {
        // get timestamp and calculate merkle hash
        let timestamp = timestamp_now();
        let merkle: String = if transactions.len() > 1 {
            merkle_hash(
                transactions[1..]
                    .iter()
                    .map(|x| hash_str(x.to_string().as_bytes()))
                    .collect(),
            )
            .expect("Block::new().merkle_hash failed")
        } else {
            String::new()
        };
        Block {
            index,
            timestamp: timestamp.clone(),
            transactions,
            previous_hash: prev_hash.clone(),
            nonce: 0,
            hash: String::new(),
            merkle: merkle.clone(),
            hash_str: format!("{}${}${}${}", index, timestamp, merkle, prev_hash),
        }
    }

    /// Json representation of block.
    pub fn as_json(&self) -> serde_json::Value {
        json!({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions.iter().map(|x| x.as_json()).collect::<Vec<serde_json::Value>>(),
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "merkle": self.merkle,
        })
    }

    /// Calculates the hash of the block using a nonce.
    /// The function also updates the hash and nonce properties of the Block and returns the hash.
    pub fn calc_hash(&mut self, nonce: u64) -> String {
        // update nonce and calculate hash
        self.nonce = nonce;
        let hash = hash_str(format!("{}${}", self.hash_str, nonce).as_bytes());
        self.hash = hash.clone();
        hash
    }

    /// Construct a block from bytes.
    pub fn from_db_data(
        idx: u64,
        head: &IVec,
        transactions: &Vec<IVec>,
    ) -> Result<Self, Box<dyn Error>> {
        // parse head to json
        let head: BlockHead = match serde_json::from_slice(head) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        // construct transactions
        let mut txs: Vec<Transaction> = Vec::new();
        for tx in transactions {
            match Transaction::from_db_data(tx) {
                Ok(n) => txs.push(n),
                Err(e) => return Err(format!("{:?}", e).into()),
            };
        }
        // construct block
        Ok(Self {
            index: idx,
            timestamp: head.timestamp,
            transactions: txs,
            previous_hash: head.previous_hash.clone(),
            nonce: head.nonce,
            hash: head.hash,
            merkle: head.merkle.clone(),
            hash_str: format!(
                "{}${}${}${}",
                idx, head.timestamp, head.merkle, head.previous_hash
            ),
        })
    }

    /// Contstruct a block from json.
    pub fn from_json(json: &serde_json::Value) -> Result<Block, Box<dyn Any + Send>> {
        // get index
        let json = json.clone();
        let idx = {
            match json.get("index") {
                Some(n) => match n.as_u64() {
                    Some(n) => n,
                    None => return Err(Box::new("parse index to u64 error")),
                },
                None => return Err(Box::new("get index error")),
            }
        };
        // get transactions
        let transactions_json = {
            match json.get("transactions") {
                Some(n) => match n.as_array() {
                    Some(n) => n.to_owned(),
                    None => return Err(Box::new("parse transactions to vector error")),
                },
                None => return Err(Box::new("get transactions error")),
            }
        };
        // check for transactions
        if transactions_json.len() < 1 && idx != 0 {
            return Err(Box::new("no transactions error"));
        }
        // construct transactions from json
        let mut transactions: Vec<Transaction> = Vec::new();
        for tx in transactions_json {
            match Transaction::from_json(&tx) {
                Ok(n) => transactions.push(n),
                Err(e) => return Err(e),
            }
        }
        // get previous hash
        let previous_hash = {
            match json.get("previous_hash") {
                Some(n) => n.to_string().replace('"', ""),
                None => return Err(Box::new("get previous hash error")),
            }
        };
        // get timestamp
        let timestamp = {
            match json.get("timestamp") {
                Some(n) => match n.as_i64() {
                    Some(n) => n,
                    None => return Err(Box::new("parse timestamp to i64 error")),
                },
                None => return Err(Box::new("get timestamp error")),
            }
        };
        // get nonce
        let nonce = {
            match json.get("nonce") {
                Some(n) => match n.as_u64() {
                    Some(n) => n,
                    None => return Err(Box::new("parse nonce to u64 error")),
                },
                None => return Err(Box::new("get nonce error")),
            }
        };
        // get hash
        let hash = {
            match json.get("hash") {
                Some(n) => n.to_string().replace('"', ""),
                None => return Err(Box::new("get hash error")),
            }
        };
        // get merkle hash
        let merkle = {
            match json.get("merkle") {
                Some(n) => n.to_string().replace('"', ""),
                None => return Err(Box::new("get merkle hash error")),
            }
        };
        // construct block
        let mut block = Self::new(idx, transactions, previous_hash.clone());

        // update values
        block.timestamp = timestamp;
        block.nonce = nonce;
        block.hash = hash;
        block.merkle = merkle.clone();
        block.hash_str = format!("{}${}${}${}", idx, timestamp, merkle, previous_hash);
        Ok(block)
    }

    /// Split the block in two seperated parts as bytes for storing it in the database.
    /// Returns: `(index, head, Vec<transactions>, positions)`
    pub fn to_db_data(&self) -> ([u8; 8], IVec, Vec<IVec>, HashMap<String, Vec<u8>>) {
        let head = json!({
            "hash": self.hash,
            "merkle": self.merkle,
            "nonce": self.nonce,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
        })
        .to_string();

        // get positions
        let mut positions: HashMap<String, Vec<u8>> = HashMap::new();
        let mut ivec_txs: Vec<IVec> = Vec::new();
        let mut idx = 0_u8;
        for tx in &self.transactions {
            // source
            let mut val = match positions.get(&tx.src) {
                Some(n) => n.to_owned(),
                None => Vec::new(),
            };
            val.push(idx);
            positions.insert(tx.src.clone(), val);

            // destination
            let mut val = match positions.get(&tx.dst) {
                Some(n) => n.to_owned(),
                None => Vec::new(),
            };
            val.push(idx);
            positions.insert(tx.dst.clone(), val);

            // parse to bytes
            ivec_txs.push(IVec::from(tx.as_json().to_string().as_bytes()));
            idx += 1;
        }
        (
            self.index.to_be_bytes(),
            IVec::from(head.as_bytes()),
            ivec_txs,
            positions,
        )
    }

    /// Performs checks on the properties of the block, recalculates it's hashes and
    /// validates its transactions.
    pub fn validate(&self, chain: &BlockChain) -> Result<(), BlockError> {
        // check hash
        if self.clone().calc_hash(self.nonce) != self.hash {
            return Err(BlockError::MismatchHash);
        }
        // check previous hash
        if self.index > 0 {
            let block = match chain.get((self.index - 1) as u64) {
                Ok(n) => match n {
                    Some(n) => n,
                    None => return Err(BlockError::BlockNotInChain),
                },
                Err(e) => {
                    eprintln!("[#] BLOCK:validate - get block from chain error: {}", e);
                    return Err(BlockError::BlockNotInChain);
                }
            };
            if self.previous_hash != block.hash {
                return Err(BlockError::MismatchPreviousHash);
            }
        }
        // prevent failing on genisis block
        else if self.index == 0 {
            return Ok(());
        }
        // check amount of transactions
        if self.transactions.len() < 1 {
            return Err(BlockError::NoCoinbaseTransaction);
        }
        // split coinbase & usual transactions
        let mut coinbase = self.transactions.clone();
        let transactions = coinbase.split_off(1);
        let coinbase = &coinbase[0];

        // check coinbase source
        if coinbase.src != *COINBASE.get().unwrap() {
            return Err(BlockError::MismatchCoinbaseSource);
        }
        // check coinbase reward
        if coinbase.val != get_blockreward(self.index) + get_fees(&transactions) {
            return Err(BlockError::InvalidReward);
        }
        // check transactions
        for t in transactions {
            match t.validate(chain) {
                Ok(()) => continue,
                Err(e) => {
                    println!("transaction invalid: {:?}", e);
                    return Err(BlockError::TransactionValidationFailed);
                }
            }
        }
        // recreate merkle hash to validate
        let merkle: String = if self.transactions.len() > 1 {
            merkle_hash(
                self.transactions[1..]
                    .iter()
                    .map(|x| hash_str(x.to_string().as_bytes()))
                    .collect(),
            )
            .expect("Block::validate().merkle_hash failed")
        } else {
            String::new()
        };
        // check merkle hash
        if merkle != self.merkle {
            return Err(BlockError::MismatchMerkleHash);
        }
        Ok(())
    }
}

impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // block head
        let mut output: String = format!(
            "> Index: {}\n> Timestamp: {}\n> Previous Hash: {}\n> Nonce: {}\n> Hash: {}\n> Transactions:\n", 
            self.index, self.timestamp, self.previous_hash, self.nonce, self.hash
        );
        // append transactions
        for t in &self.transactions {
            output = format!("{}\n{}", output, t);
        }
        write!(f, "{}", output)
    }
}

impl PartialEq for Block {
    fn eq(&self, block: &Self) -> bool {
        // compare essential parts of block
        if ![
            self.index.to_string(),
            self.previous_hash.clone(),
            self.merkle.clone(),
        ]
        .iter()
        .zip([
            block.index.to_string(),
            block.previous_hash.clone(),
            block.merkle.clone(),
        ])
        .all(|(x, y)| x.to_owned() == y.to_owned())
        {
            return false;
        }
        // compare timestamp with deviation
        let dev = 60 * 5;
        if !((self.timestamp - dev)..(self.timestamp + dev)).contains(&block.timestamp) {
            return false;
        }
        true
    }
}

#[derive(Clone)]
pub struct BlockChain {
    heads_db: Db,
    transactions_db: Db,
    position_db: Db,
    syncing: Arc<Mutex<SyncState>>,
}

impl BlockChain {
    /// Constructor
    pub fn new() -> Result<BlockChain, Box<dyn Error>> {
        let heads_db = match sled::open(DB_HEAD_PATH.get().unwrap()) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        let transactions_db = match sled::open(DB_TXS_PATH.get().unwrap()) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        let position_db = match sled::open(DB_POS_PATH.get().unwrap()) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        Ok(BlockChain {
            heads_db,
            transactions_db,
            position_db,
            syncing: Arc::new(Mutex::new(SyncState::Ready)),
        })
    }

    /// Adds a block to the chain after checking its integrity
    pub fn add_block(&mut self, block: &Block) -> Result<(), BlockChainError> {
        // check if block already in chain
        if self.contains(block.index) {
            return Err(BlockChainError::BlockAlreadyInChain);
        }
        // get latest block
        let latest = match self.last() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN::add_block - get latest block error: {}", e);
                return Err(BlockChainError::DatabaseError);
            }
        };
        // check integrity
        match latest {
            Some(n) => {
                // check index
                if n.index + 1 != block.index {
                    return Err(BlockChainError::InvalidIndex);
                }
                // check previous hash
                if n.hash != block.previous_hash && n.index > 1 {
                    return Err(BlockChainError::InvalidPreviousHash);
                }
                // check date
                if n.timestamp > block.timestamp {
                    return Err(BlockChainError::InvalidTimeStamp);
                }
            }
            None => {
                // check index
                if block.index != 0 {
                    return Err(BlockChainError::InvalidIndex);
                }
            }
        }
        // split block
        let (idx, head, txs, pos) = block.to_db_data();

        // insert block heads
        let _ = self.heads_db.insert(&idx, head);

        // open transaction trees
        let transactions_tree = match self.transactions_db.open_tree(&idx) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] BLOCKCHAIN::add_block - open transactions tree error: {}",
                    e
                );
                return Err(BlockChainError::DatabaseError);
            }
        };
        // insert transactions
        for i in 0..txs.len() {
            let _ = transactions_tree.insert(&[i as u8], &txs[i]);
        }
        // insert positions
        for (addr, idxs) in pos {
            // open address tree
            let positions_tree = match self.position_db.open_tree(&addr) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!(
                        "[#] BLOCKCHAIN::add_block - open positions tree error: {}",
                        e
                    );
                    return Err(BlockChainError::DatabaseError);
                }
            };
            // update & insert indices
            let _ = positions_tree.insert(idx, idxs);
        }
        Ok(())
    }

    /// Check if blockchain is synchronized.
    /// Only returns `SyncState::Fine` with an empty list of peers and an index of 0.
    /// Returns `SyncState::Needed` with the corresponding peers and the index to start syncing
    /// from.
    pub fn check(&self, peers: &Vec<String>) -> Result<(SyncState, Vec<String>, u64), CheckError> {
        // map latest blocks of the network
        let map = collect_map::<String>(&peers, Dtype::GetBlock, "-1");

        // get hash of latest block that most nodes share
        let hash_network = match get_key_by_vec_len(map.clone()) {
            Some(n) => n,
            None => return Err(CheckError::GetValueNone),
        };
        // get latest block of local chain
        let latest_block = match self.last() {
            Ok(n) => match n {
                Some(n) => n,
                None => return Ok((SyncState::Needed, map[&hash_network].clone(), 0)),
            },
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN - check sync get latest block error: {}", e);
                return Err(CheckError::GetValueError);
            }
        };
        // check equality of hash
        if latest_block.hash == hash_network {
            return Ok((SyncState::Fine, vec![], 0));
        }
        // otherwise determine index of start of invalid chain
        // choose peer
        let peer = match map[&hash_network].choose(&mut thread_rng()) {
            Some(n) => n,
            None => unsafe { &ARGS.get().unwrap().node },
        };
        // craft request
        let req = Request {
            dtype: Dtype::GetBlock,
            data: "-1",
            addr: peer.to_owned(),
        };
        // request latest block
        let stream = match request(peer, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN - check sync request block error: {}", e);
                return Err(CheckError::Request);
            }
        };
        // receive latest block
        let res: Response<String> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN - check sync receive block error: {}", e);
                return Err(CheckError::Receive);
            }
        };
        // parse to json
        let data: GetBlockReceiver = match serde_json::from_str(&res.res) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] BLOCKCHAIN - check sync parse response to json error: {}",
                    e
                );
                return Err(CheckError::ParseJson);
            }
        };
        // request blocks backwards until matching
        let mut idx: u64 = data.len - 1;
        loop {
            let (mut hash1, mut hash2) = (String::new(), String::new());
            for peer in &map[&hash_network] {
                // craft request
                let req = Request {
                    dtype: Dtype::GetBlock,
                    data: idx.to_string(),
                    addr: peer.to_owned(),
                };
                // request block
                let stream = match request(&peer, &req) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[#] BLOCKCHAIN - check sync request block error: {}", e);
                        return Err(CheckError::Request);
                    }
                };
                // receive block
                let res: Response<String> = match receive(stream) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[#] BLOCKCHAIN - check sync receive block error: {}", e);
                        return Err(CheckError::Receive);
                    }
                };
                // parse to json
                let data: GetBlockReceiver = match serde_json::from_str(&res.res) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!(
                            "[#] BLOCKCHAIN - check sync parse response to json error: {}",
                            e
                        );
                        return Err(CheckError::ParseJson);
                    }
                };
                // construct block
                let block = match Block::from_json(&data.block) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[#] BLOCKCHAIN - check sync construct block error: {:?}", e);
                        return Err(CheckError::Construction);
                    }
                };
                // get hash of local block
                let local_hash = match self.get(block.index) {
                    Ok(n) => match n {
                        Some(n) => n.hash,
                        None => String::new(),
                    },
                    Err(e) => {
                        eprintln!("[#] BLOCKCHAIN - check sync get block error: {:?}", e);
                        return Err(CheckError::GetValueError);
                    }
                };
                // compare
                hash1 = block.hash;
                hash2 = local_hash;
                if hash1 == hash2 || idx == 0 {
                    break;
                }
                // decrease index
                idx -= 1;
            }
            if hash1 == hash2 || idx == 0 {
                break;
            }
        }
        Ok((SyncState::Needed, map[&hash_network].clone(), idx))
    }

    /// Clear the entire blockchain.
    fn clear(&self) -> Result<(), sled::Error> {
        // transactions & positions
        for db in [&self.transactions_db, &self.position_db] {
            for name in db.tree_names() {
                if name.starts_with(b"__") {
                    continue;
                }
                match db.drop_tree(name) {
                    Ok(_) => (),
                    Err(e) => return Err(e),
                };
            }
            match db.flush() {
                Ok(_) => (),
                Err(e) => return Err(e),
            }
        }
        // heads
        match self.heads_db.clear() {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
        match self.heads_db.flush() {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        println!("[#] BLOCKCHAIN - clear databases successful");
        Ok(())
    }

    /// Check if blockchain already contains a block.
    pub fn contains(&self, idx: u64) -> bool {
        match self.heads_db.contains_key(&idx.to_be_bytes()) {
            Ok(n) => {
                if n {
                    return true;
                }
            }
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN - check if block in chain error: {}", e);
                return true;
            }
        };
        false
    }

    /// Construct the blockchain with a genisis block.
    pub fn create_genisis(&mut self) -> Result<(), BlockChainError> {
        // new chain & genisis block
        match self.clear() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] BLOCKCHAIN - clear databases error: {}", e);
                exit(1);
            }
        };
        let mut genisis_block = Block::new(0, vec![], String::new());
        genisis_block.calc_hash(0); // calc hash of block
        println!("DEBUG - genisis block:\n{}", genisis_block);
        self.add_block(&mut genisis_block)
    }

    /// Return block by index.
    pub fn get(&self, idx: u64) -> Result<Option<Block>, Box<dyn Error>> {
        // get block head
        let head = match self.heads_db.get(idx.to_be_bytes()) {
            Ok(n) => match n {
                Some(n) => n,
                None => return Ok(None),
            },
            Err(e) => return Err(Box::new(e)),
        };
        // get transactions
        let tx_tree = match self.transactions_db.open_tree(idx.to_be_bytes()) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        // parse transactions
        let mut tx_data: Vec<IVec> = Vec::new();
        for i in tx_tree.iter() {
            let (_, data) = match i {
                Ok(n) => n,
                Err(e) => return Err(Box::new(e)),
            };
            tx_data.push(data);
        }
        // construct block
        match Block::from_db_data(idx, &head, &tx_data) {
            Ok(n) => Ok(Some(n)),
            Err(e) => Err(e),
        }
    }

    /// Returns the latest block of the chain.
    pub fn last(&self) -> Result<Option<Block>, Box<dyn Error>> {
        // get block head
        let (idx, head) = match self.heads_db.last() {
            Ok(n) => match n {
                Some(n) => n,
                None => return Ok(None),
            },
            Err(e) => return Err(Box::new(e)),
        };
        // get transactions
        let tx_tree = match self.transactions_db.open_tree(&idx) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        // parse transactions
        let mut tx_data: Vec<IVec> = Vec::new();
        for i in tx_tree.iter() {
            let (_, data) = match i {
                Ok(n) => n,
                Err(e) => return Err(Box::new(e)),
            };
            tx_data.push(data);
        }
        // construct block
        let idx = match u8_to_u64_vec(&idx) {
            Ok(n) => n[0],
            Err(_) => return Err("parse u8 array to u64 error".into()),
        };
        match Block::from_db_data(idx, &head, &tx_data) {
            Ok(n) => Ok(Some(n)),
            Err(e) => Err(e),
        }
    }

    /// Get addresses by patterns.
    fn get_addr_by_pat(&self, pattern: &Vec<u8>) -> Result<Vec<String>, Box<dyn Error>> {
        let mut out = Vec::new();
        for i in self.position_db.tree_names() {
            if addr_to_pattern(&i) == *pattern {
                match String::from_utf8(i.to_vec()) {
                    Ok(n) => out.push(n),
                    Err(e) => return Err(Box::new(e)),
                }
            } else {
                continue;
            }
        }
        Ok(out)
    }

    /// Get amount of coins of an address.
    pub fn get_balance(&self, addr: &str) -> Result<f64, Box<dyn Error>> {
        // get transactions
        let transactions = match self.get_transactions(addr) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        // calculate value
        let mut value = 0_f64;
        let now = timestamp_now();
        for tx in transactions {
            if tx.src == addr {
                value -= tx.val + tx.fee;
            } else if &tx.dst == addr {
                // note timestamp
                if tx.timestamp <= now {
                    value += tx.val;
                }
            }
        }
        Ok(value)
    }

    /// Returns a list of transactions of an address.
    fn get_transactions(&self, addr: &str) -> Result<Vec<Transaction>, sled::Error> {
        // open positions tree
        let positions_tree = match self.position_db.open_tree(&addr) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        // iterate through positons
        let mut out = Vec::new();
        for i in positions_tree.iter() {
            // get indices
            let (block_idx, tx_idxs) = match i {
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            println!(
                "DEBUG - get transactions: block idx:{:?}\nDEBUG - get transactions: tx idxs:{:?}",
                &block_idx, tx_idxs
            ); // DEBUG

            // get transaction
            let tx_tree = match self.transactions_db.open_tree(block_idx) {
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            // DEBUG
            for i in tx_tree.iter().keys() {
                println!("DEBUG - get transactions: tx_tree key: {:?}", i.unwrap());
                // DEBUG
            }
            for x in tx_idxs.to_vec() {
                let tx_data = match tx_tree.get(&[x]) {
                    Ok(n) => match n {
                        Some(n) => n,
                        None => continue,
                    },
                    Err(e) => return Err(e),
                };
                // construct transaction
                let tx = match Transaction::from_db_data(&tx_data) {
                    Ok(n) => n,
                    Err(e) => {
                        return Err(sled::Error::Unsupported(format!(
                            "construct transaction error: {:?}",
                            e
                        )))
                    }
                };
                out.push(tx);
            }
        }
        Ok(out)
    }

    /// Returns a list of transactions where the source address matches a specific pattern.
    pub fn get_txs_by_pat(&self, pattern: &Vec<u8>) -> Result<Vec<Transaction>, Box<dyn Error>> {
        // get addresses
        let addresses = match self.get_addr_by_pat(pattern) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        println!(
            "DEBUG - get transactions by pattern: addresses: {:?}",
            addresses
        ); // DEBUG

        // get transactions
        let mut out: Vec<Transaction> = Vec::new();
        for addr in addresses {
            let txs = match self.get_transactions(&addr) {
                Ok(n) => n,
                Err(e) => return Err(Box::new(e)),
            };
            out.extend_from_slice(&txs);
        }
        println!(
            "DEBUG - get transactions by pattern: transactions: {:?}",
            out
        ); // DEBUG
        Ok(out)
    }

    /// Return the length of the blockchain.
    pub fn len(&self) -> usize {
        self.heads_db.len()
    }

    /// Remove a block from the chain.
    fn remove(&self, idx: u64) -> Result<(), sled::Error> {
        // remove head
        match self.heads_db.remove(&idx.to_be_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        // remove transactions
        match self.transactions_db.drop_tree(&idx.to_be_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        // remove positions - I know it's not the most efficient way
        for i in self.position_db.tree_names() {
            let tree = match self.position_db.open_tree(i) {
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            match tree.remove(&idx.to_be_bytes()) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };
        }
        Ok(())
    }

    /// Remove all blocks until a specific index from chain.
    fn remove_until(&self, idx: u64) -> Result<(), sled::Error> {
        println!("DEBUG - REMOVE UNTIL: {}", idx); // DEBUG
        if idx == 0 {
            return self.clear();
        }
        let length = self.len() as u64;
        for i in idx..length {
            println!("DEBUG - remove: {}", i); // DEBUG
            match self.remove(i) {
                Ok(_) => (),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Synchronize blockchain by a node.
    /// Everything is fine if it returns:
    ///
    ///     `SyncState::Running`    - it's syncing right now
    ///     `SyncState::Ready`      - it's done
    ///
    /// Everything else is either not returned or is an error.
    pub fn sync(&mut self, addr: &str, mut idx: u64) -> Result<SyncState, Box<dyn Error>> {
        {
            // check if currently syncing
            let mut state = self.syncing.lock().unwrap();
            match *state {
                SyncState::Ready => {
                    // set syncing state
                    *state = SyncState::Running;
                }
                _ => return Ok(SyncState::Running),
            }
        }
        println!("[+] BLOCKCHAIN:SYNC - updating blockchain");

        // remove blocks
        let length = self.len() as u64;
        println!("DEBUG - sync: length: {}", length); // debug
        println!("DEBUG - sync: idx: {}", idx); // debug
        match self.remove_until(idx) {
            Ok(_) => (),
            Err(e) => {
                eprintln!(
                    "[#] BLOCKCHAIN:SYNC - remove blocks from chain error: {}",
                    e
                );
                return Err(Box::new(e));
            }
        }
        let length = self.len() as u64; // DEBUG
        println!("DEBUG - sync: length: {}", length); // debug

        // get blocks from other node
        let mut length = idx + 1;
        while idx < length {
            // craft request
            let req = Request {
                dtype: Dtype::GetBlock,
                data: idx.to_string(),
                addr: ADDR.get().unwrap().to_string(),
            };

            println!("DEBUG - Request: {:?}", req); // DEBUG

            // send request
            let stream = match request(addr, &req) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - get block error: {}", e);
                    return Err(e);
                }
            };
            // receive data
            let response: Response<String> = match receive(stream) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - receive block error: {}", e);
                    return Err(e);
                }
            };
            // parse to json
            let data: GetBlockReceiver = match serde_json::from_str(response.res.as_str()) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - parsing to json error: {:?}", e);
                    continue;
                }
            };
            // update length
            length = data.len;

            // construct block
            let block = match Block::from_json(&data.block) {
                Ok(n) => n,
                Err(e) => {
                    println!("DEBUG - block json {:#?}", &data.block); // DEBUG
                    eprintln!("[#] BLOCKCHAIN:SYNC - parsing block error: {:?}", e);
                    continue;
                }
            };
            // add block to chain
            match self.add_block(&block) {
                Ok(_) => {
                    idx += 1;
                    println!("[+] BLOCKCHAIN:SYNC - [ {} / {} ]", idx, length);
                }
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - adding block error: {}", e);
                    exit(1); // DEBUG
                }
            }
        }
        println!("[+] BLOCKCHAIN:SYNC - blockchain update successful");
        {
            // set syncing state
            *self.syncing.lock().unwrap() = SyncState::Ready;
        }
        Ok(SyncState::Ready)
    }
}

#[derive(Clone)]
pub struct MineController {
    pub wallet: Arc<String>,
    pub sync_addr: Arc<Mutex<String>>,
    blockchain: Arc<Mutex<BlockChain>>,
    transactionpool: Arc<Mutex<TransactionPool>>,
    peers: Arc<Mutex<Vec<String>>>,
    run_send: Arc<Mutex<mpsc::Sender<bool>>>,
    run_recv: Arc<Mutex<mpsc::Receiver<bool>>>,
    pub current_block: Arc<Mutex<Block>>,
    pub measured_times: Arc<Mutex<Vec<f64>>>,
    sleep: Arc<Duration>,
}

impl MineController {
    /// Constructor
    pub fn new(
        wallet: &str,
        sync_addr: &str,
        blockchain: &Arc<Mutex<BlockChain>>,
        transactionpool: &Arc<Mutex<TransactionPool>>,
        peers: &Arc<Mutex<Vec<String>>>,
        measured_times: &Arc<Mutex<Vec<f64>>>,
    ) -> Self {
        let (send, recv) = mpsc::channel();
        MineController {
            wallet: Arc::new(wallet.to_string()),
            sync_addr: Arc::new(Mutex::new(sync_addr.to_string())),
            blockchain: blockchain.clone(),
            transactionpool: transactionpool.clone(),
            peers: peers.clone(),
            run_send: Arc::new(Mutex::new(send)),
            run_recv: Arc::new(Mutex::new(recv)),
            current_block: Arc::new(Mutex::new(Block::default())),
            sleep: Arc::new(Duration::from_millis(500)),
            measured_times: {
                let mut a = Arc::new(Mutex::new(Vec::with_capacity(2)));
                Arc::clone_from(&mut a, measured_times);
                a
            },
        }
    }

    /// Check if currently mined block is synchronized.
    /// Only returns `SyncState::Fine` with an empty list of peers and `SyncState::Needed` with the
    /// corresponding peers.
    pub fn check(&self, peers: &Vec<String>) -> Result<(SyncState, Vec<String>), SyncError> {
        // map currently mined blocks of the network
        let map = collect_map::<String>(&peers, Dtype::GetBlock, "-2");

        // get hash of latest block that most nodes share
        let hash_network = match get_key_by_vec_len(map.clone()) {
            Some(n) => n,
            None => return Err(SyncError::InvalidValue),
        };
        // get hash of latest block of local chain
        let hash_local = { self.current_block.lock().unwrap().hash.clone() };

        // check equality of hash
        if hash_local == hash_network {
            Ok((SyncState::Fine, vec![]))
        } else {
            Ok((SyncState::Needed, map[&hash_network].clone()))
        }
    }

    /// Construct the command to run the miner.
    fn command(start: u64, block: Block) -> Result<Child, std::io::Error> {
        // serialize data
        let plain = json!({
            "start": start,
            "difficulty": unsafe { DIFFICULTY.get().unwrap().to_string() },
            "hash_data": block.hash_str,
        })
        .to_string();
        let data = &STANDARD.encode(&plain); // encode using base64

        // run miner
        Command::new("./target/release/miner")
            .args([data])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    /// Set next block to be mined.
    /// Returns `true` if block was set and `false` if not.
    fn next_block(&self) -> Result<bool, TryLockError<u8>> {
        let mut pool = {
            // lock pool
            let mut pool = match self.transactionpool.lock() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("[#] MINECONTROLLER - acquire transactionpool error");
                    return Err(TryLockError::WouldBlock);
                }
            };
            // flush it
            match pool.flush() {
                Some(n) => n,
                None => vec![],
            }
        };
        let prev_block = {
            // lock chain
            let chain = match self.blockchain.lock() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("[#] MINECONTROLLER - acquire blockchain error");
                    return Err(TryLockError::WouldBlock);
                }
            };
            // get latest block
            match chain.last() {
                Ok(n) => match n {
                    Some(n) => n,
                    None => {
                        eprintln!(
                            "[#] MINECONTROLLER - get previous block error: no previous block"
                        );
                        return Ok(false);
                    }
                },
                Err(e) => {
                    eprintln!("[#] MINECONTROLLER - get previous block error: {:?}", e);
                    return Ok(false);
                }
            }
        };
        let idx = prev_block.index + 1;

        // calc block reward
        let reward = get_blockreward(idx) + get_fees(&pool);

        // coinbase transaction
        let coinbase_tx = match Transaction::get_coinbase(reward) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] MINECONTROLLER - get coinbase transaction error: {}", e);
                return Ok(false);
            }
        };
        // collect transactions
        let mut transactions = vec![coinbase_tx];
        transactions.append(&mut pool);

        // construct block
        let block = Block::new(idx, transactions, prev_block.hash);

        // update current_block property
        match self.current_block.lock() {
            Ok(mut n) => *n = block,
            Err(_) => return Err(TryLockError::WouldBlock),
        }
        Ok(true)
    }

    // TODO: split some functionality of this function in multiple functions
    /// Run the miner.
    pub fn run(&self, genisis: bool, sync: bool) {
        // synchronize block to mine
        if !genisis && sync {
            match self.sync(&self.current_block) {
                Ok(_) => {
                    println!("DEBUG - currently mined block synchronized"); // DEBUG
                }
                Err(e) => {
                    panic!("[#] MINECONTROLLER:SYNC - synchronization error: {}", e);
                }
            };
        } else {
            // otherwise get next block to mine from chain
            match self.next_block() {
                Ok(n) => {
                    if !n {
                        panic!("[#] MINECONTROLLER - set next block failed");
                    }
                }
                Err(e) => {
                    panic!("[#] MINECONTROLLER - set next block error: {}", e);
                }
            };
        }
        let self_arc: Arc<MineController> = Arc::new(self.clone());
        thread::spawn(move || {
            loop {
                // measurements
                let start_nonce: u64 = thread_rng().gen(); // calculate hashrate based on incrementation
                                                           // since start value
                let start_time = timestamp_now();

                let mut stderr: Option<ChildStderr> = None;
                let block: Option<Block> = loop {
                    // get block to mine
                    let mut block = { self_arc.current_block.lock().unwrap().clone() };

                    // DEBUG
                    println!("DEBUG - currenlty mined block: \n{}", block);

                    // set up miner
                    let mut miner: Child = {
                        match MineController::command(start_nonce, block.clone()) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[#] MINER - error: {}", e);
                                break None;
                            }
                        }
                    };
                    stderr = miner.stderr.take();

                    // start mining
                    println!("[+] MINER - mining...");

                    // IO of child process
                    let stdout = Arc::new(Mutex::new(BufReader::new(miner.stdout.take().unwrap())));
                    let mut stdin = BufWriter::new(miner.stdin.take().unwrap());

                    // check for skip signal
                    let check_skip = {
                        let self_arc = Arc::clone(&self_arc);
                        thread::spawn(move || match self_arc.run_recv.lock().unwrap().recv() {
                            Ok(_) => println!("[+] MINER - received skip signal"),
                            Err(e) => {
                                eprintln!("[#] MINER - receive skip signal error: {:?}", e)
                            }
                        })
                    };
                    // read thread
                    let read = {
                        let stdout = Arc::clone(&stdout);
                        thread::spawn(move || {
                            let mut buf = Vec::new();
                            let _ = stdout.lock().unwrap().read_to_end(&mut buf);
                            buf
                        })
                    };
                    // while mining
                    while !read.is_finished() {
                        if check_skip.is_finished() {
                            match stdin.write_all("stop\n".as_bytes()) {
                                Ok(_) => {
                                    println!("[+] MINER - move on to next block");
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("[#] MINER - child process stdin error: {}", e);
                                }
                            }
                        }
                        thread::sleep(*self_arc.sleep);
                    }
                    // kill process
                    match miner.kill() {
                        Ok(_) => (),
                        Err(e) => eprintln!("[#] MINER - kill child process error: {}", e),
                    }
                    match miner.wait() {
                        Ok(_) => (),
                        Err(e) => eprintln!("[#] MINER - child process exit error: {}", e),
                    }
                    // ensure check_skip thread is finished
                    if !check_skip.is_finished() {
                        self_arc.send_stop();
                    } else {
                        let mut times = self_arc.measured_times.lock().unwrap();
                        times.push(timestamp_now() as f64 - start_time as f64);
                        println!("DEBUG - times: {:?}", times); // DEBUG

                        if times.len() % 2 == 0 {
                            let expected = unsafe { ARGS.get().unwrap().expected };
                            println!("DEBUG - expected: {}", expected); // DEBUG
                            let difficulty = calc_new_target(expected, &times);
                            println!("DEBUG - new difficulty: {:?}", difficulty); // DEBUG
                            times.clear();

                            unsafe {
                                // update difficulty
                                match DIFFICULTY.get_mut() {
                                    Some(n) => {
                                        *n = match difficulty {
                                            Ok(n) => n,
                                            Err(_) => {
                                                eprintln!("[#] MINER - calculate difficulty error");
                                                n.to_owned()
                                            }
                                        }
                                    }
                                    None => eprintln!("[#] MINER - update difficulty error"),
                                }
                            }
                        }

                        println!("DEBUG - here I could measure the time"); // DEBUG
                        continue;
                    }
                    // process output
                    let buf = read.join().unwrap();
                    let foo: [u8; 8] = match buf.try_into() {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[#] MINER - parse bytes to nonce error: {:?}", e);
                            break None;
                        }
                    };
                    let nonce = u64::from_be_bytes(foo);

                    // update block
                    block.calc_hash(nonce);
                    break Some(block);
                };
                // measure time
                let stop_time = timestamp_now();

                // retrieve block
                let block = match block {
                    Some(n) => n,
                    None => {
                        let mut buf = String::new();
                        match stderr {
                            Some(mut n) => {
                                let _ = n.read_to_string(&mut buf);
                                eprintln!("{}", buf);
                            }
                            None => eprintln!("[#] MINER - retrieve block error"),
                        }
                        break;
                    }
                };
                {
                    // validate block
                    match block.validate(&self_arc.blockchain.lock().unwrap()) {
                        Ok(_) => println!("[+] MINER - nonce found: {}", block.nonce),
                        Err(e) => {
                            eprintln!("[#] MINER - block invalid: {:?}", e);
                            break;
                        }
                    }
                }
                // measurements
                println!(
                    "DEBUG - start: {}\nDEBUG - stop:  {}",
                    start_time, stop_time
                ); // DEBUG
                println!(
                    "DEBUG - block time needed: {} minutes",
                    (stop_time as f64 - start_time as f64) / 60_f64
                ); // DEBUG
                let hashrate = {
                    if stop_time - start_time != 0 {
                        ((block.nonce - start_nonce) / (stop_time - start_time) as u64) as f64
                    } else {
                        (block.nonce - start_nonce) as f64
                    }
                };
                let mut times = self_arc.measured_times.lock().unwrap();

                println!("[+] MINER - hashrate: {}/sec", hashrate);
                times.push((stop_time as f64 - start_time as f64) / 60_f64);
                println!("DEBUG - times: {:?}", times); // DEBUG

                if times.len() % 2 == 0 {
                    let expected = unsafe { ARGS.get().unwrap().expected };
                    println!("DEBUG - expected: {}", expected); // DEBUG
                    let difficulty = calc_new_target(expected, &times);
                    println!("DEBUG - new difficulty: {:?}", difficulty); // DEBUG
                    times.clear();

                    unsafe {
                        // update difficulty
                        match DIFFICULTY.get_mut() {
                            Some(n) => {
                                *n = match difficulty {
                                    Ok(n) => n,
                                    Err(_) => {
                                        eprintln!("[#] MINER - calculate difficulty error");
                                        n.to_owned()
                                    }
                                }
                            }
                            None => eprintln!("[#] MINER - update difficulty error"),
                        }
                    }
                }
                {
                    // broadcast block & update peers
                    let responses: Vec<Response<PostBlockResponse>>;
                    let failed: Vec<String>;
                    let responses = {
                        let mut peers = self_arc.peers.lock().unwrap(); // lock peers

                        // broadcast block
                        (responses, failed) = broadcast::<PostBlockResponse>(
                            &peers,
                            Dtype::PostBlock,
                            &block.as_json().to_string(),
                        );
                        *peers = subtract_vec(peers.to_vec(), failed); // update peers
                        responses // return peers
                    };
                    // declare variables for check
                    let mut agree: Vec<String> = Vec::new();
                    let mut disagree: Vec<String> = Vec::new();

                    // deserialize responses
                    for res in responses {
                        if res.res == PostBlockResponse::Success {
                            agree.push(res.addr);
                        } else {
                            disagree.push(res.addr);
                        }
                    }
                    // compare responses
                    if disagree.len() > (agree.len() + disagree.len()) / 2 {
                        println!("[+] MINER - synchronize node...");
                        break;
                    } else {
                        // request resync of peers of nodes who disagreed
                        println!("[+] MINER - network accepted block");
                        broadcast::<CheckSyncResponse>(&disagree, Dtype::CheckSync, "");
                    }
                }
                {
                    // append block to chain
                    let mut chain = self_arc.blockchain.lock().unwrap();
                    match chain.add_block(&block) {
                        Ok(_) => println!("[+] MINER - block added:\n\n{}", block),
                        Err(e) => eprintln!("[#] MINER - adding block error: {:?}", e),
                    }
                }
                // next block to mine
                match self_arc.next_block() {
                    Ok(n) => {
                        if !n {
                            eprintln!("[#] MINER - set next block failed");
                        }
                    }
                    Err(e) => {
                        eprintln!("[#] MINER - set next block error: {:?}", e);
                    }
                }
            }
            {
                // synchronize node if necessary
                let peers = self_arc.peers.lock().unwrap();
                {
                    // blockchain
                    let mut chain = self_arc.blockchain.lock().unwrap();
                    let (state, peers, idx) = match chain.check(&peers) {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[#] MINER - check blockchain error: {:?}", e);
                            (SyncState::Error, vec![], 0)
                        }
                    };
                    if state != SyncState::Error {
                        match state {
                            SyncState::Fine => println!("[+] BLOCKCHAIN - state: fine"),
                            SyncState::Needed => {
                                // sync blockchain
                                match chain.sync(
                                    peers.choose(&mut thread_rng()).expect(
                                        "[#] MINER - random peer for blockchain sync error",
                                    ),
                                    idx,
                                ) {
                                    Ok(n) => match n {
                                        SyncState::Ready => (),
                                        SyncState::Running => (),
                                        _ => panic!(
                                            "[#] BLOCKCHAIN:SYNC - synchronization failed: {:?}",
                                            n
                                        ),
                                    },
                                    Err(e) => eprintln!(
                                        "[#] BLOCKCHAIN:SYNC - synchronization error: {}",
                                        e
                                    ),
                                };
                            }
                            _ => (),
                        }
                    }
                }
                {
                    // transactionpool
                    let mut pool = self_arc.transactionpool.lock().unwrap();
                    let (state, peers) = match pool.check(&peers) {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[#] MINER - check transactionpool error: {:?}", e);
                            (SyncState::Error, vec![])
                        }
                    };
                    if state != SyncState::Error {
                        match state {
                            SyncState::Fine => println!("[+] TRANSACTIONPOOL - state: fine"),
                            SyncState::Needed => {
                                // sync transactionpool
                                match pool.sync(peers.choose(&mut thread_rng())
                                        .expect("[#] MINER - random peer for transactionpool sync error")) {
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
                    let (state, peers) = match self_arc.check(&peers) {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[#] MINER - check minecontroller error: {:?}", e);
                            (SyncState::Error, vec![])
                        }
                    };
                    if state != SyncState::Error {
                        match state {
                            SyncState::Fine => println!("[+] MINECONTROLLER - state: fine"),
                            SyncState::Needed => {
                                // set sync address
                                *self_arc.sync_addr.lock().unwrap() = peers
                                    .choose(&mut thread_rng())
                                    .expect("[#] MINER - random peer for minecontroller sync error")
                                    .to_string();
                                // sync minecontroller
                                match self_arc.sync(&self_arc.current_block) {
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
        });
    }

    /// Send the stop signal to the miner.
    /// Returns bool of success.
    fn send_stop(&self) -> bool {
        match self.run_send.lock().unwrap().send(true) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] MINER - skip current block failed: {:?}", e);
                return false;
            }
        }
        true
    }

    /// Drop currently mined block and set next one.
    /// Returns bool of success.
    pub fn skip(&self) -> bool {
        if !self.send_stop() {
            return false;
        }
        match self.next_block() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] MINER - set next block error: {:?}", e);
                false
            }
        }
    }

    /// Synchronize the currently mined block.
    /// Returns `SyncState::Ready` if everything worked fine.
    pub fn sync(&self, current_block: &Arc<Mutex<Block>>) -> Result<SyncState, SyncError> {
        // get address for synchronizing
        let addr = { self.sync_addr.lock().unwrap().clone() };

        // craft request
        let req = Request {
            dtype: Dtype::GetBlock,
            data: "-2",
            addr: ADDR.get().unwrap().to_string(),
        };
        // send request
        let stream = match request(&addr, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] MINECONTROLLER:SYNC - get block error: {}", e);
                return Err(SyncError::Request);
            }
        };
        // receive data
        let response: Response<String> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] MINECONTROLLER:SYNC - receive block error: {}", e);
                return Err(SyncError::Receive);
            }
        };
        // DEBUG
        println!("DEBUG - MINECONTROLLER:SYNC received: {:?}", response);
        // parse to json
        let data = match serde_json::Value::from_str(response.res.as_str()) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] MINECONTROLLER:SYNC - parsing to json error: {:?}", e);
                return Err(SyncError::InvalidValue);
            }
        };
        // construct block
        let mut block = match Block::from_json(&data) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] MINECONTROLLER:SYNC - parsing block error: {:?}", e);
                return Err(SyncError::InvalidValue);
            }
        };
        // get transactions
        let transactions = match block.transactions.get(1..) {
            Some(n) => n.to_vec(),
            None => return Err(SyncError::InvalidValue),
        };
        // calc block reward
        let reward = get_blockreward(block.index) + get_fees(&transactions);

        // coinbase transaction
        let coinbase_tx = match Transaction::get_coinbase(reward) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] MINECONTROLLER:SYNC - get coinbase transaction error: {}",
                    e
                );
                return Err(SyncError::InvalidValue);
            }
        };
        // update coinbase transaction
        block.transactions[0] = coinbase_tx;

        // set block
        *current_block.lock().unwrap() = block;
        Ok(SyncState::Ready)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    pub src: String,        // Address of sender
    pub dst: String,        // Address of receiver
    pub val: f64,           // Amount of coins
    pub timestamp: i64,     // when transaction will be valid
    pub signature: Vec<u8>, // signature
    pub pub_key: Vec<u8>,   // public key
    pub broadcast: bool,    // should the transaction be broadcasted - always true
    pub fee: f64,           // Address of node to receive it's fees
}

impl Transaction {
    // Constructor
    pub fn new(src: &str, dst: &str, val: f64, after: &str) -> Result<Self, Box<dyn Error>> {
        let add = match get_timestamp(after) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        Ok(Transaction {
            src: src.to_string(),
            dst: dst.to_string(),
            val,
            timestamp: timestamp_now() + add,
            signature: Vec::new(),
            pub_key: Vec::new(),
            broadcast: true,
            fee: calc_fee(val),
        })
    }

    pub fn as_json(&self) -> serde_json::Value {
        json!({
            "src": self.src,
            "dst": self.dst,
            "val": self.val,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "pub_key": self.pub_key,
            "broadcast": self.broadcast,
            "fee": self.fee,
        })
    }

    /// Check signature.
    fn check_sign(&self) -> Result<bool, ErrorStack> {
        // load public key
        let pkey = match PKey::public_key_from_pem(&self.pub_key) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        // construct verifier
        let mut verifier = match Verifier::new(MessageDigest::sha1(), &pkey) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        // feed the verifier with delicious data
        match verifier.update(self.signature_fmt().as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] TRANSACTION:verify - update verifier error: {}", e);
                return Err(e);
            }
        };
        // verify
        verifier.verify(&self.signature)
    }

    /// Construct a transaction from database serialized data.
    pub fn from_db_data(data: &IVec) -> Result<Self, Box<dyn Any + Send>> {
        // parse to string
        let data = match String::from_utf8(data.to_vec()) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        // parse to json
        let json = match serde_json::Value::from_str(&data) {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        // construct transaction
        Self::from_json(&json)
    }

    /// Construct a transaction from json.
    pub fn from_json(json: &serde_json::Value) -> Result<Transaction, Box<dyn Any + Send>> {
        catch_unwind(|| {
            // initial data
            Transaction {
                src: json
                    .get("src")
                    .expect("Transaction::from_json: src")
                    .to_string()
                    .replace('"', ""),
                dst: json
                    .get("dst")
                    .expect("Transaction::from_json: dst")
                    .to_string()
                    .replace('"', ""),
                val: json
                    .get("val")
                    .expect("Transaction::from_json: val")
                    .as_f64()
                    .expect("Transaction::from_json: val as f64"),
                timestamp: json
                    .get("timestamp")
                    .expect("Transaction::from_json: timestamp")
                    .as_i64()
                    .expect("Transaction::from_json: timestamp as i64"),
                signature: json
                    .get("signature")
                    .expect("Transaction::from_json: signature")
                    .as_array()
                    .expect("Transaction::from_json: signature as array")
                    .iter()
                    .map(|x| {
                        x.as_u64()
                            .expect("Transaction::from_json: signature value as u64")
                            as u8
                    })
                    .collect(),
                pub_key: json
                    .get("pub_key")
                    .expect("Transaction::from_json: public key")
                    .as_array()
                    .expect("Transaction::from_json: public key as array")
                    .iter()
                    .map(|x| {
                        x.as_u64()
                            .expect("Transaction::from_json: public key value as u64")
                            as u8
                    })
                    .collect(),
                broadcast: json
                    .get("broadcast")
                    .expect("Transaction::from_json: broadcast")
                    .as_bool()
                    .expect("Transaction::from_json: broadcast as bool"),
                fee: json
                    .get("fee")
                    .expect("Trnasaction::from_json: fee")
                    .as_f64()
                    .expect("Transaction::from_json: fee as f64"),
            }
        })
    }

    /// Generate the coinbase transaction.
    pub fn get_coinbase(reward: f64) -> Result<Self, Box<dyn Error>> {
        let wallet = unsafe { &ARGS.get().unwrap().wallet };
        let addr = COINBASE.get().unwrap().to_string();
        let mut transaction = match Transaction::new(&addr, &wallet, reward, "") {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        transaction.fee = 0.0;
        Ok(transaction)
    }

    /// Signature format for signing and checking signature.
    fn signature_fmt(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}-{:#?}",
            self.src, self.dst, self.timestamp, self.fee, self.val, self.pub_key
        )
    }

    /// Serialize the transaction for storing it in the database.
    pub fn to_db_data(&self) -> IVec {
        IVec::from(self.as_json().to_string().as_bytes())
    }

    /// Check entire transaction.
    pub fn validate(&self, chain: &BlockChain) -> Result<(), TVE> {
        // check source
        match check_addr_by_key(&self.src, &self.pub_key) {
            Ok(n) => {
                if !n {
                    println!("DEBUG - CASE 1"); // DEBUG
                    return Err(TVE::InvalidSource);
                }
            }
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTION:validate - check source by key error: {}",
                    e
                );
                return Err(TVE::InvalidSource);
            }
        }
        match check_addr_by_sum(&self.src) {
            Ok(n) => {
                if !n {
                    println!("DEBUG - CASE 2"); // DEBUG
                    return Err(TVE::InvalidSource);
                }
            }
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTION:validate - check source by sum error: {}",
                    e
                );
                return Err(TVE::InvalidSource);
            }
        }
        // check destination
        match check_addr_by_sum(&self.dst) {
            Ok(n) => {
                if !n {
                    return Err(TVE::InvalidDestination);
                }
            }
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTION:validate - check destination by sum error: {}",
                    e
                );
                return Err(TVE::InvalidDestination);
            }
        }
        // check value
        if self.val < 0.0 {
            return Err(TVE::InvalidValue);
        }
        // check fee
        if self.fee != calc_fee(self.val) {
            return Err(TVE::InvalidFee);
        }
        // check balance
        let balance = match chain.get_balance(&self.src) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] TRANSACTION:validate - check balance error: {}", e);
                return Err(TVE::BalanceError);
            }
        };
        if balance < self.val + self.fee {
            return Err(TVE::InvalidBalance);
        }
        // check signature
        match self.check_sign() {
            Ok(n) => {
                if !n {
                    return Err(TVE::InvalidSignature);
                }
            }
            Err(e) => {
                eprintln!("[#] TRANSACTION:validate - check signature error: {}", e);
                return Err(TVE::SignatureError);
            }
        }
        Ok(())
    }
}
impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\t- Source: {}\n\t- Destination: {}\n\t- Timestamp: {}\n\t- Value: {}\n\t- Fee: {}\n",
            self.src, self.dst, self.timestamp, self.val, self.fee
        )
    }
}
impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        // compare essential parts of transaction
        if ![
            self.src.clone(),
            self.dst.clone(),
            self.val.to_string(),
            self.timestamp.to_string(),
        ]
        .iter()
        .zip([
            other.src.clone(),
            other.dst.clone(),
            other.val.to_string(),
            other.timestamp.to_string(),
        ])
        .all(|(x, y)| x.to_owned() == y.to_owned())
            || ![self.signature.clone(), self.pub_key.clone()]
                .iter()
                .zip([other.signature.clone(), other.pub_key.clone()])
                .all(|(x, y)| x.to_owned() == y.to_owned())
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TransactionPool {
    pub pool: Vec<Transaction>,
    pub tx_per_block: u16,
}

impl TransactionPool {
    /// Constructor
    pub fn new(txpb: u16) -> Self {
        TransactionPool {
            pool: Vec::new(),
            tx_per_block: txpb,
        }
    }

    /// Adds a transaction to the pool after ensuring it's not already contained.
    pub fn add(&mut self, transaction: &Transaction) -> Result<(), PoolError> {
        // check if transaction already in pool
        if self.pool.contains(transaction) {
            return Err(PoolError::DuplicatedTransaction);
        }
        // add transaction to pool
        self.pool.push(transaction.clone());
        Ok(())
    }

    /// Check if the transactionpool is synchronized.
    /// Only returns `SyncState::Fine` with an empty list of peers and `SyncState::Needed` with the
    /// corresponding peers.
    pub fn check(&self, peers: &Vec<String>) -> Result<(SyncState, Vec<String>), SyncError> {
        // map transactionpool merkle hashes
        let map = collect_map::<String>(&peers, Dtype::GetPoolHash, "");

        // get hash of latest block that most nodes share
        let hash_network = match get_key_by_vec_len(map.clone()) {
            Some(n) => n,
            None => return Err(SyncError::InvalidValue),
        };
        // get merkle hash of local transactionpool
        let hashes_local: Vec<String> = self
            .pool
            .iter()
            .map(|x| hash_str(x.to_string().as_bytes()))
            .collect();
        let hash_local = match merkle_hash(hashes_local) {
            Some(n) => n,
            None => String::new(),
        };
        // check equality of hashes
        if hash_local != hash_network {
            return Ok((SyncState::Needed, map[&hash_network].clone()));
        }
        // check transactions per block
        let map_txpb = collect_map::<u16>(&peers, Dtype::GetTransactionsPerBlock, "");
        let network_txpb: u16 = match get_key_by_vec_len(map_txpb) {
            Some(n) => n,
            None => {
                eprintln!("[#] TRANSACTIONPOOL:CHECK - check transactions per block failed");
                return Err(SyncError::InvalidValue);
            }
        };
        // check equality of txpb
        if network_txpb != self.tx_per_block {
            return Ok((SyncState::Needed, map[&hash_network].clone()));
        }
        Ok((SyncState::Fine, vec![]))
    }

    /// Flush a specific amount of transactions from the pool and return them.
    pub fn flush(&mut self) -> Option<Vec<Transaction>> {
        // get amount of transactions to flush
        let amount: usize = {
            if usize::from(self.tx_per_block) <= self.pool.len() {
                self.tx_per_block as usize
            } else {
                self.pool.len()
            }
        };
        // retrieve the transactions that are going to be flushed
        let flushed = match self.pool.get(0..amount) {
            Some(n) => n.to_vec(),
            None => return None,
        };
        // update pool & return flushed
        self.pool = subtract_vec(self.pool.clone(), flushed.clone());
        Some(flushed)
    }

    /// Synchronize pool.
    /// Everything is fine if it returns:
    ///
    ///     `SyncState::Ready`      - it's done
    ///
    /// Everything else is either not returned or is an error.
    pub fn sync(&mut self, addr: &str) -> Result<SyncState, SyncError> {
        println!("[+] TRANSACTIONPOOL:SYNC - synchronizing transaction pool");

        // synchronize transactions per block
        let req = Request {
            dtype: Dtype::GetTransactionsPerBlock,
            data: "",
            addr: ADDR.get().unwrap().to_string(),
        };
        // send request
        let stream = match request(addr, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] TRANSACTIONPOOL:SYNC - request txpb error: {}", e);
                return Err(SyncError::Request);
            }
        };
        // receive data
        let response: Response<u16> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] TRANSACTIONPOOL:SYNC - receive txpb error: {}", e);
                return Err(SyncError::Receive);
            }
        };
        // update txpb
        self.tx_per_block = response.res;
        println!(
            "[+] TRANSACTIONPOOL:SYNC - update txpb successful: {}",
            self.tx_per_block
        );

        // synchronize transactions
        let req = Request {
            dtype: Dtype::GetTransactionPool,
            data: "",
            addr: ADDR.get().unwrap().to_string(),
        };
        // send request
        let stream = match request(addr, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTIONPOOL:SYNC - request transaction pool error: {}",
                    e
                );
                return Err(SyncError::Request);
            }
        };
        // receive data
        let response: Response<Vec<String>> = match receive(stream) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTIONPOOL:SYNC - receive transaction pool error: {}",
                    e
                );
                return Err(SyncError::Receive);
            }
        };
        let transactions = response.res;
        for i in transactions {
            // parse to json
            let i: serde_json::Value = match serde_json::Value::from_str(&i) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!(
                        "[#] TRANSACTIONPOOL:SYNC - parse transaction to json error: {}",
                        e
                    );
                    continue;
                }
            };
            // construct Transaction
            let transaction = match Transaction::from_json(&i) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!(
                        "[#] TRANSACTIONPOOL:SYNC - transaction construction error: {:?}",
                        e
                    );
                    continue;
                }
            };
            // add transaction to pool
            match self.add(&transaction) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("[#] TRANSACTIONPOOL:SYNC - add transaction error: {:?}", e);
                    continue;
                }
            }
        }
        // remove invalid transactions & update transaction pool
        println!("[+] TRANSACTIONPOOL:SYNC - transactionpool update successful");
        Ok(SyncState::Ready)
    }
}

impl std::fmt::Display for TransactionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();
        for i in &self.pool {
            output = format!("{}\n{}", output, i);
        }
        write!(f, "{}", output)
    }
}
