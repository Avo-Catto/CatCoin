use crate::{comm::*, utils::*};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{seq::SliceRandom, thread_rng, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    any::Any,
    error::Error,
    io::{BufReader, BufWriter, Read, Write},
    panic::catch_unwind,
    process::{exit, Child, Command, Stdio},
    str::FromStr,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
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
    hash_str: String,
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

impl Block {
    /// Constructor
    pub fn new(index: u64, transactions: Vec<Transaction>, prev_hash: String) -> Block {
        // get timestamp and calculate merkle hash
        let timestamp = timestamp_now();
        let merkle: String = match transactions.is_empty() {
            true => String::new(),
            false => merkle_hash(transactions.iter().map(|x| x.hash.clone()).collect())
                .expect("Block::new().merkle_hash failed"),
        };
        Block {
            index,
            timestamp: timestamp.clone(),
            transactions,
            previous_hash: prev_hash,
            nonce: 0,
            hash: String::new(),
            merkle: merkle.clone(),
            hash_str: format!("{}${}${}", index, timestamp, merkle),
        }
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

    /// Performs regex checks on the properties of the block, recalculates it's hashes and
    /// validates its transactions.
    pub fn validate(&self) -> Result<(), BlockError> {
        // check if values of block are valid using regex
        let sha256_re = Regex::new("^[a-fA-F0-9]{64}$").unwrap();

        // check previous hash
        if !sha256_re.is_match(&self.previous_hash) && self.index != 0 {
            return Err(BlockError::MismatchPreviousHash);
        }
        // check hash
        if self.clone().calc_hash(self.nonce) != self.hash {
            return Err(BlockError::MismatchHash);
        }
        // check transactions
        for t in &self.transactions {
            match t.validate() {
                Ok(()) => continue,
                Err(e) => {
                    println!("transaction invalid: {:?}", e);
                    return Err(BlockError::TransactionValidationFailed);
                }
            }
        }
        // recreate merkle hash to validate
        let merkle = match self.transactions.is_empty() {
            true => String::new(),
            false => merkle_hash(self.transactions.iter().map(|x| x.hash.clone()).collect())
                .expect("Block::validate().merkle_hash failed"),
        };
        // check merkle hash
        if merkle != self.merkle {
            return Err(BlockError::MismatchMerkleHash);
        }
        Ok(())
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

    /// Contstruct a block from json.
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
            json.get("index")
                .unwrap()
                .as_u64()
                .expect("Block::from_json: index"),
            transactions,
            json.get("previous_hash")
                .unwrap()
                .to_string()
                .replace('"', ""),
        );
        // update values
        block.timestamp = json
            .get("timestamp")
            .unwrap()
            .as_i64()
            .expect("Block::from_json: timestamp");
        block.nonce = json
            .get("nonce")
            .unwrap()
            .as_u64()
            .expect("Block::from_json: nonce");
        block.hash = json.get("hash").unwrap().to_string().replace("\"", "");
        block.merkle = json.get("merkle").unwrap().to_string().replace("\"", "");
        block.hash_str = format!("{}${}${}", block.index, block.timestamp, block.merkle);
        Ok(block)
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

#[derive(Clone)]
pub struct BlockChain {
    chain: Vec<Block>,
    syncing: Arc<Mutex<SyncState>>,
}

impl BlockChain {
    /// Constructor
    pub fn new() -> BlockChain {
        BlockChain {
            chain: Vec::new(),
            syncing: Arc::new(Mutex::new(SyncState::Ready)),
        }
    }

    /// Construct the blockchain with a genisis block.
    pub fn new_with_genisis() -> BlockChain {
        let mut chain = Self::new(); // new chain
        let mut genisis_block = Block::new(0, Vec::new(), String::new()); // new block
        genisis_block.calc_hash(0); // calc hash of block
        let _ = chain.add_block(&genisis_block); // append block to chain
        chain
    }

    /// Adds a block to the chain after checking if it's not already in chain and the index and
    pub fn add_block(&mut self, block: &Block) -> Result<(), BlockChainError> {
        // check if block already in chain
        if self.chain.contains(block) {
            return Err(BlockChainError::BlockAlreadyInChain);
        }
        // check integrity
        match self.chain.last() {
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
        self.chain.push(block.clone()); // add block to chain
        Ok(())
    }

    /// Updates the chain.
    /// `Note:` The entire chain will be deleted!
    pub fn set_chain(&mut self, chain: Vec<Block>) -> Result<(), Box<dyn Error>> {
        self.chain.clear();
        for block in &chain {
            // check block
            match block.validate() {
                Ok(_) => (),
                Err(e) => return Err(Box::new(e)),
            }
            // add to chain
            match self.add_block(block) {
                Ok(_) => (),
                Err(e) => return Err(Box::new(e)),
            }
        }
        Ok(())
    }

    /// Return block by index.
    pub fn get(&self, idx: usize) -> Option<&Block> {
        self.chain.get(idx)
    }

    /// Returns the blockchain.
    pub fn get_chain(&self) -> Vec<Block> {
        self.chain.clone()
    }

    /// Returns the latest block of the chain.
    pub fn get_latest(&self) -> Result<Block, ()> {
        // check if none
        let latest = self.chain.last();
        if latest.is_none() {
            Err(())
        } else {
            Ok(latest.unwrap().clone())
        }
    }

    /// Synchronize blockchain by a node.
    pub fn sync(&mut self, addr: &str) -> Result<SyncState, Box<dyn Error>> {
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
        self.chain.clear(); // clear chain

        // get blocks from other node
        let mut length: u64 = 2;
        let mut idx: u64 = 0;

        // TODO: I can just length - 1 for testing purpose
        while idx < length {
            // craft request
            let req = Request {
                dtype: Dtype::GetBlock,
                data: idx.to_string(),
            };
            // send request
            let stream = match request(addr, &req) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - get block error: {}", e);
                    continue;
                }
            };
            // receive data
            let response: Response<String> = match receive(stream) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - receive block error: {}", e);
                    continue;
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
            // construct block
            let block = match Block::from_json(&data.block) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[#] BLOCKCHAIN:SYNC - parsing block error: {:?}", e);
                    continue;
                }
            };
            // add block to chain
            match self.add_block(&block) {
                Ok(_) => {
                    idx += 1;
                    length = data.len;
                    println!("[+] BLOCKCHAIN:SYNC - [ {} / {} ]", idx, length);
                }
                Err(e) => eprintln!("[#] BLOCKCHAIN:SYNC - adding block error: {}", e),
            }
        }
        println!("[+] BLOCKCHAIN:SYNC - blockchain update successful");
        {
            // set syncing state
            *self.syncing.lock().unwrap() = SyncState::Ready;
        }
        Ok(SyncState::Fine)
    }
}

#[derive(Deserialize)]
struct MineReceiver {
    nonce: u64,
    hash: String,
    merkle: String,
}

#[derive(Clone)]
pub struct MineController {
    blockchain: Arc<Mutex<BlockChain>>,
    transactionpool: Arc<Mutex<TransactionPool>>,
    peers: Arc<Mutex<Vec<String>>>,
    difficulty: Arc<Mutex<u8>>,
    run_send: Arc<Mutex<mpsc::Sender<bool>>>,
    run_recv: Arc<Mutex<mpsc::Receiver<bool>>>,
    pub current_block: Arc<Mutex<Block>>,
    sleep: Arc<Duration>, // TODO: make it configurable
}

impl MineController {
    /// Constructor
    pub fn new(
        blockchain: &Arc<Mutex<BlockChain>>,
        transactionpool: &Arc<Mutex<TransactionPool>>,
        peers: &Arc<Mutex<Vec<String>>>,
        difficulty: &Arc<Mutex<u8>>,
    ) -> MineController {
        let (send, recv) = mpsc::channel();
        MineController {
            blockchain: blockchain.clone(),
            transactionpool: transactionpool.clone(),
            peers: peers.clone(),
            difficulty: difficulty.clone(),
            run_send: Arc::new(Mutex::new(send)),
            run_recv: Arc::new(Mutex::new(recv)),
            current_block: Arc::new(Mutex::new(Block::default())),
            sleep: Arc::new(Duration::from_millis(500)),
        }
    }

    // TODO: compile miner
    /// Construct the command to run the miner.
    fn command(start: u64, difficulty: u8, block: Block) -> Result<Child, std::io::Error> {
        // format data
        let plain = format!(
            "{{\"start\":{},\"difficulty\":{},\"block\":{}}}",
            start,
            difficulty,
            block.as_json()
        );
        Command::new("cargo")
            .args(["run", "--bin", "miner", "-q", "--", &STANDARD.encode(plain)])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
    }

    /// Run the miner.
    pub fn run(&self) {
        let self_arc: Arc<MineController> = Arc::new(self.clone());
        thread::spawn(move || {
            loop {
                // clone and lock required mutex objects
                let chain = { self_arc.blockchain.lock().unwrap().clone() };
                let mut pool = {
                    let mut lock = self_arc.transactionpool.lock().unwrap();
                    let tmp = lock.clone();
                    lock.flush();
                    tmp
                };
                let prev_block = match chain.get_latest() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("[#] MINER - get previous block error");
                        exit(1);
                    }
                };
                // construct block
                let mut block =
                    Block::new(prev_block.index + 1, pool.pool.clone(), prev_block.hash);
                pool.flush(); // flush pool
                {
                    // update current_block property
                    *self_arc.current_block.lock().unwrap() = block.clone();
                }
                // set up miner
                let miner = {
                    let mut rng = thread_rng();
                    MineController::command(
                        rng.gen(), // random number
                        *self_arc.difficulty.lock().unwrap(),
                        block.clone(),
                    )
                };
                // start mining
                println!("[+] MINER - mining...");
                match miner {
                    Ok(mut child) => {
                        // IO of child process
                        let stdout =
                            Arc::new(Mutex::new(BufReader::new(child.stdout.take().unwrap())));
                        let mut stdin = BufWriter::new(child.stdin.take().unwrap());

                        // check for skip signal
                        let check_skip = {
                            let self_arc = Arc::clone(&self_arc);
                            thread::spawn(move || match self_arc.run_recv.lock().unwrap().recv() {
                                Ok(_) => println!("[+] MINER - received skip signal"),
                                Err(e) => {
                                    eprintln!("[#] MINER - receive skip signal error: {:?}", e);
                                }
                            })
                        };
                        // read thread
                        let read = {
                            let stdout = Arc::clone(&stdout);
                            thread::spawn(move || {
                                let mut buf = String::new();
                                let _ = stdout.lock().unwrap().read_to_string(&mut buf);
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
                        // ensure check_skip thread is finished
                        if !check_skip.is_finished() {
                            self_arc.skip();
                        } else {
                            continue;
                        }
                        // decode base64
                        let buf = read.join().unwrap();
                        let decoded = match STANDARD.decode(buf.as_bytes()) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[#] MINER - decode base64 error: {}", e);
                                return;
                            }
                        };
                        // convert u8 vector to string
                        let json_string = match String::from_utf8(decoded) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[#] MINER - convert utf8 error: {}", e);
                                return;
                            }
                        };
                        // parse string to json
                        let json: MineReceiver = match serde_json::from_str(&json_string) {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[#] MINER - parse json error: {}", e);
                                return;
                            }
                        };
                        // update block
                        block.nonce = json.nonce;
                        block.hash = json.hash;
                        block.merkle = json.merkle;
                    }
                    Err(e) => {
                        eprintln!("[#] MINER - error: {}", e);
                        return;
                    }
                }
                // validate block
                match block.validate() {
                    Ok(_) => println!("[+] MINER - nonce found: {}", block.nonce),
                    Err(e) => {
                        eprintln!("[#] MINER - block invalid: {:?}", e);
                        return;
                    }
                }
                {
                    // TODO: it blocks the mining process I guess
                    // broadcast block & update peers
                    let responses: Vec<Response<PostBlockResponse>>;
                    let failed: Vec<String>;

                    let (peers, responses) = {
                        println!("DEBUG - checking responses of nodes!"); // debug
                        let mut peers = self_arc.peers.lock().unwrap(); // lock peers

                        // broadcast block
                        (responses, failed) = broadcast::<PostBlockResponse>(
                            &peers,
                            Dtype::PostBlock,
                            &block.as_json().to_string(),
                        );
                        *peers = subtract_vec(peers.to_vec(), failed); // update peers
                        (peers, responses) // return peers
                    };

                    // declare variables for check
                    let mut agree: Vec<String> = Vec::new();
                    let mut disagree: Vec<String> = Vec::new();

                    // DEBUG
                    println!("DEBUG - peers: {:?}", peers);
                    println!("DEBUG - responses: {:?}", responses);

                    // deserialize responses
                    for res in responses {
                        if res.res == PostBlockResponse::Success {
                            agree.push(res.addr);
                        } else {
                            disagree.push(res.addr);
                        }
                    }

                    // DEBUG
                    println!("DEBUG - agree: {:?}", agree);
                    println!("DEBUG - disagree: {:?}", disagree);

                    // compare responses
                    if disagree.len() > (agree.len() + disagree.len()) / 2 {
                        println!("DEBUG - more than 50% of the nodes disagreed with the block"); // DEBUG

                        // stop mining // TODO: I have to stop the miner in any way and start
                        // mining after the resync
                        if !self_arc.skip() {
                            eprintln!("MINER - stop miner error: ?"); // DEBUG
                        };

                        // collect hashes and find hash where most peers agreed with
                        let map = collect_map(&peers, Dtype::GetLatestHash, "");
                        let key = match get_key_by_vec_len(map.clone()) {
                            Some(n) => n,
                            None => continue,
                        };

                        // ensure the chain wasn't updated already
                        let latest = {
                            self_arc
                                .blockchain
                                .lock()
                                .unwrap()
                                .get_latest()
                                .unwrap()
                                .clone()
                        };
                        if key == latest.hash {
                            // TODO: fix that chain resyncs 4 times
                            continue;
                        }

                        // resync blockchain // TODO: make it better
                        for _ in 0..map[&key].len() {
                            // get random address
                            let addr = map[&key].choose(&mut thread_rng()).unwrap();
                            println!("DEBUG - peer to sync from: {}", addr);

                            // resync blockchain
                            match self_arc.blockchain.lock().unwrap().sync(addr) {
                                Ok(_) => break,
                                Err(e) => {
                                    eprintln!("[#] BLOCKCHAIN:SYNC - failed check error: {}", e);
                                }
                            }
                        }
                        continue;
                    } else {
                        // request resync of peers of nodes who disagreed
                        println!("[+] MINER - network accepted block");
                        broadcast::<CheckBlockchainResponse>(
                            &disagree,
                            Dtype::CheckBlockchain,
                            &String::new(),
                        );
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
            }
        });
    }

    /// Drop currently mined block and return bool of succeed.
    pub fn skip(&self) -> bool {
        match self.run_send.lock().unwrap().send(true) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("[#] MINER - skip current block failed: {:?}", e);
                false
            }
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub src: String,
    pub dst: String,
    pub timestamp: i64,
    pub val: f64,
    pub broadcast: bool,
    pub hash: String,
}

impl Transaction {
    /// Contstructor
    pub fn new(src: &str, dst: &str, val: f64, broadcast: bool) -> Transaction {
        let timestamp = timestamp_now();
        let hash_fmt = format!("{}${}${}${}", src, dst, timestamp, val);

        // construct transaction
        Transaction {
            src: String::from_str(src).unwrap(),
            dst: String::from_str(dst).unwrap(),
            timestamp,
            val,
            broadcast,
            hash: hash_str(hash_fmt.as_bytes()),
        }
    }

    /// Construct a transaction from json.
    pub fn from_json(json: &serde_json::Value) -> Result<Transaction, Box<dyn Any + Send>> {
        let transaction = catch_unwind(|| {
            let mut transaction = Self::new(
                json.get("src")
                    .expect("Transaction::from_json: src")
                    .as_str()
                    .expect("Transaction::from_json: src as str"),
                json.get("dst")
                    .expect("Transaction::from_json: dst")
                    .as_str()
                    .expect("Transaction::from_json: dst as str"),
                json.get("val")
                    .expect("Transaction::from_json: val")
                    .as_f64()
                    .expect("Transaction::from_json: val as f64"),
                json.get("broadcast")
                    .expect("Transaction::from_json: broadcast")
                    .as_bool()
                    .expect("Transaction::from_json: broadcast as bool"),
            );
            transaction.timestamp = json
                .get("timestamp")
                .expect("Transaction::from_json: timestamp")
                .as_i64()
                .expect("Transaction::from_json: timestamp as i64");
            transaction.hash = json
                .get("hash")
                .expect("Transaction::from_json: hash")
                .to_string()
                .replace("\"", "");
            transaction
        });
        transaction
    }

    /// Json representation of the transaction.
    pub fn as_json(&self) -> serde_json::Value {
        json!({
            "src": self.src,
            "dst": self.dst,
            "timestamp": self.timestamp,
            "val": self.val,
            "broadcast": self.broadcast,
            "hash": self.hash,
        })
    }

    /// Recalculate the hash of the transaction and return it.
    fn recalc_hash(&self) -> String {
        let hash_fmt = format!("{}${}${}${}", self.src, self.dst, self.timestamp, self.val);
        hash_str(hash_fmt.as_bytes())
    }

    /// Performs regex checks on the properties of the transaction and recalculates its hash.
    pub fn validate(&self) -> Result<(), TVE> {
        // check if values of transaction are valid
        let uuid_re = Regex::new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").unwrap();

        // checksrc
        if !uuid_re.is_match(&self.src) {
            return Err(TVE::MismatchSource);
        }
        // check dst
        if !uuid_re.is_match(&self.dst) {
            return Err(TVE::MismatchDestination);
        }
        // check hash
        if self.recalc_hash() != self.hash {
            return Err(TVE::MismatchHash);
        }
        Ok(())
    }
}

impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\t- Source: {}\n\t- Destination: {}\n\t- Timestamp: {}\n\t- Value: {}\n\t- Hash: {}\n",
            self.src, self.dst, self.timestamp, self.val, self.hash
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TransactionPool {
    pub pool: Vec<Transaction>,
}

impl TransactionPool {
    /// Constructor
    pub fn new() -> TransactionPool {
        TransactionPool { pool: Vec::new() }
    }

    /// Adds a transaction to the pool after ensuring it's not already contained.
    pub fn add(&mut self, transaction: &Transaction) -> Result<(), PoolError> {
        // check if transaction already in pool
        if self.pool.contains(transaction) {
            return Err(PoolError::DuplicatedTransaction);
        }
        match transaction.validate() {
            Ok(_) => (),
            Err(_) => return Err(PoolError::InvalidTransaction),
        }
        self.pool.push(transaction.clone()); // add transaction to pool
        Ok(())
    }

    /// Clears all transactions from pool.
    pub fn flush(&mut self) {
        self.pool.clear();
    }

    /// Synchronize pool.
    pub fn sync(&mut self, addr: &str) -> Result<SyncState, Box<dyn Error>> {
        println!("[+] TRANSACTIONPOOL:SYNC - updating transaction pool");

        // craft request
        let req = Request {
            dtype: Dtype::GetTransactionPool,
            data: "",
        };
        // send request
        let stream = match request(addr, &req) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTIONPOOL:SYNC - request transaction pool error: {}",
                    e
                );
                exit(1);
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
                exit(1);
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
        Ok(SyncState::Fine)
    }
}
