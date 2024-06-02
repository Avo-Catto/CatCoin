// use crate::blockchain::BlockChain;
use crate::{
    blockchain::Transaction,
    comm::*,
    share::{ADDR, ARGS, COINBASE, FEE},
};
use chrono::Utc;
use num_bigint::BigUint;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha224, Sha256, Sha512};
use std::{
    collections::HashMap,
    error::Error,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

#[derive(Deserialize)]
struct ArgsReceiver {
    difficulty: u8,
    tx_per_block: u16,
    reward: f64,
    halving: u64,
    fee: u8,
}

#[derive(Debug)]
pub enum BlockError {
    InvalidReward,
    TransactionValidationFailed,
    MismatchCoinbaseSource,
    MismatchPreviousHash,
    MismatchHash,
    MismatchMerkleHash,
    NoCoinbaseTransaction,
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for BlockError {}

#[derive(Debug)]
pub enum BlockChainError {
    BlockAlreadyInChain,
    InvalidIndex,
    InvalidPreviousHash,
    InvalidTimeStamp,
}

impl std::fmt::Display for BlockChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for BlockChainError {}

#[derive(Debug)]
pub enum SyncError {
    InvalidValue,
    Receive,
    Request,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for SyncError {}

#[derive(Debug)]
pub enum PoolError {
    DuplicatedTransaction,
    InvalidTransaction,
}
impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for PoolError {}

#[derive(Debug, PartialEq)]
pub enum SyncState {
    Error,
    Fine,
    Needed,
    Ready,
    Running,
}

#[derive(Debug)]
pub enum TransactionValidationError {
    BalanceError,
    InvalidFee,
    InvalidSource,
    InvalidSignature,
    InvalidDestination,
    InvalidValue,
    SignatureError,
    InvalidBalance,
}
pub type TVE = TransactionValidationError;

/// Convert address to pattern.
pub fn addr_to_pattern(addr: &str) -> Vec<u8> {
    let out: Vec<u8> = addr.bytes().map(|x| x % 2).collect();
    out
}

/// Calculate the fee of a transaction by it's value.
pub fn calc_fee(val: f64) -> f64 {
    let fee = *FEE.get().unwrap();
    let fee = fee as f64;
    val * (fee / 100.0)
}

/// Validate an address.
pub fn check_addr_by_key(addr: &str, pub_key: &Vec<u8>) -> Result<bool, Box<dyn Error>> {
    // check length
    if !check_addr_len(addr) {
        return Ok(false);
    }
    println!("DEBUG - 1"); // DEBUG
                           // decode address
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    };
    println!("DEBUG - 2"); // DEBUG
                           // extract salt & index
    let salt = String::from_utf8_lossy(&decoded[21..33]).to_string();
    let idx: u32 = match String::from_utf8_lossy(&decoded[33..]).parse() {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    };

    // DEBUG
    println!("DEBUG - 3"); // DEBUG
    let check_addr = gen_address(pub_key, idx, &salt);
    println!("ADDRESS: {}\nINDEX: {}\nSALT: {}", check_addr, idx, salt);
    // DEBUG

    // validate address
    if check_addr != addr {
        return Ok(false);
    }
    println!("DEBUG - 4"); // DEBUG
    Ok(true)
}

/// Check address by checksum.
pub fn check_addr_by_sum(addr: &str) -> Result<bool, Box<dyn Error>> {
    // check length
    if !check_addr_len(addr) {
        return Ok(false);
    }
    // decode address
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    };
    // compare checksums
    Ok(Sha224::digest(&decoded[5..])[..5] == decoded[..5])
}

/// Check length of address.
pub fn check_addr_len(addr: &str) -> bool {
    addr.as_bytes().len() > 46
}

/// Performs a regex check for an address.
/// Example: 127.0.0.1:8080 - valid
pub fn check_ip(addr: &String) -> bool {
    let addr_re = Regex::new(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})$"
    ).unwrap();
    addr_re.is_match(addr)
}

/// Performs a regex check for a SHA256 hash.
pub fn check_sha256(hash_str: &String) -> bool {
    let sha256_re = Regex::new("^[a-fA-F0-9]{64}$").unwrap();
    sha256_re.is_match(hash_str)
}

/// Compile the miner if necessary.
pub fn compile_miner() -> Result<(), Box<dyn Error>> {
    // compile miner
    let mut child = match Command::new("cargo")
        .args(["build", "-r", "--bin", "miner"])
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    };
    // wait until finished
    match child.wait() {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}

/// Collect all responses and addresses of nodes on a specific request. The response will be the
/// key and the list of peers who sent the same responses will be the value.
pub fn collect_map(peers: &Vec<String>, dtype: Dtype, data: &str) -> HashMap<String, Vec<String>> {
    let (responses, _) = broadcast::<String>(peers, dtype, data);
    let mut collection = HashMap::new();
    for i in responses {
        // check if hash already in map and add address otherwise create new entry
        collection
            .entry(i.res)
            .and_modify(|peers: &mut Vec<String>| peers.push(i.addr.clone()))
            .or_insert(vec![i.addr]);
    }
    collection
}

/// Returns the target value.
pub fn difficulty_from_u8(difficulty: u8) -> BigUint {
    // get hash difficulty
    let pat = "F".repeat(usize::from(difficulty));
    let to = "0".repeat(usize::from(difficulty));
    let hex_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        .replacen(&pat, &to, 1);
    BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap()
}

/// Generate an address.
/// Structure: `{checksum 4}:{hash 32}:{salt 4}:{index}`
pub fn gen_address(pub_key: &Vec<u8>, idx: u32, salt: &String) -> String {
    // hash public key
    let mut a = Sha512::digest(pub_key).to_vec();
    let mut b = a.clone();

    // append salt & index for uniqueness
    b.extend_from_slice(format!("{}{}", salt, idx).as_bytes());
    a.extend_from_slice(&Sha512::digest(&b));

    // hash again
    let mut c = md5::compute(Sha256::digest(&a[32..96])).to_vec();
    c.extend_from_slice(format!("{}{}", salt, idx).as_bytes());

    // checksum
    let checksum = &Sha224::digest(&c)[..5];
    let mut result = checksum.to_vec();
    result.extend_from_slice(&c);

    // encode address
    let f = bs58::encode(result).into_string();
    f
}

/// Calculate the current blockreward by the index of the current block.
pub fn get_blockreward(idx: u64) -> f64 {
    let args = unsafe { ARGS.get().unwrap() };
    args.reward * 0.5_f64.powf((idx / args.halving) as f64)
}

/// Calculate the sum of all fees of the given transactions.
pub fn get_fees(txs: &Vec<Transaction>) -> f64 {
    let mut out = 0_f64;
    txs.iter().for_each(|x| out += x.fee);
    out
}

/// Function to get the key of a HashMap by the length of the value.
pub fn get_key_by_vec_len<V>(map: HashMap<String, Vec<V>>) -> Option<String> {
    let mut max = match map.keys().last() {
        Some(n) => n.to_string(),
        None => return None,
    };
    for key in map.keys() {
        // check if length of vec is greater
        if map[key].len() > map[&max].len() {
            max = key.clone();
        }
    }
    Some(max)
}

/// Get the timestamp by human notation.
/// Example:
/// 2m:3h:5d:2w - valid after 2 minutes, 3 hours, 5 days, 2 weeks
pub fn get_timestamp(syntax: &str) -> Result<i64, Box<dyn Error>> {
    let syntax = syntax.to_string();
    if syntax.len() < 3 {
        return Ok(0);
    }
    let mut out = 0_i64;
    for i in syntax.split(':') {
        let (multi, t) = i.split_at(i.len() - 1);
        let multi: i64 = match multi.parse() {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        match t {
            "m" => out += 60 * multi,
            "h" => out += 60 * 60 * multi,
            "d" => out += 60 * 60 * 24 * multi,
            "w" => out += 60 * 60 * 24 * 7 * multi,
            _ => (),
        }
    }
    Ok(out)
}

/// Returns the SHA256 hash of a byte array.
pub fn hash_str(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Recursive function that hashes all strings of a vector in pairs together to one hash using SHA256.
pub fn merkle_hash(data: Vec<String>) -> Option<String> {
    // check if list is empty
    if data.len() == 0 {
        return None;
    }
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

    // merge two elements & hash it
    for i in (0..len).step_by(2) {
        hash_input = format!("{}${}", data[i], data[i + 1]);
        hash = hash_str(hash_input.as_bytes());
        output.push(hash);
    }
    if !even {
        // append hash of last element if not even
        hash = hash_str(data[len].as_bytes());
        output.push(hash);
    }
    if len > 1 {
        merkle_hash(output) // if elements left
    } else if output.len() == 1 {
        Some(output[0].clone()) // return output
    } else {
        None
    }
}

/// Removes the elements of y from x.
pub fn subtract_vec<T: PartialEq>(mut x: Vec<T>, y: Vec<T>) -> Vec<T> {
    for i in y {
        match x.iter().position(|y| y == &i) {
            Some(n) => x.remove(n),
            None => continue,
        };
    }
    x
}

/// Returns `SyncState::Ready` if the synchronization succeeds.
pub fn sync_args(addr: &str) -> Result<SyncState, SyncError> {
    println!("[+] ARGS:SYNC - updating arguments");

    // craft request
    let req = Request {
        dtype: Dtype::GetArgs,
        data: "",
        addr: ADDR.get().unwrap().to_string(),
    };
    // connect to node
    let stream = match request(addr, &req) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] ARGS:SYNC - request args error: {}", e);
            return Err(SyncError::Request);
        }
    };
    // receive args
    let response: Response<String> = match receive(stream) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] ARGS:SYNC - receive args error: {}", e);
            return Err(SyncError::Receive);
        }
    };
    // parse json from string
    let json: ArgsReceiver = match serde_json::from_str(&response.res) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] ARGS:SYNC - parse json error: {}", e);
            return Err(SyncError::InvalidValue);
        }
    };
    unsafe {
        // update args
        match ARGS.get_mut() {
            Some(args) => {
                args.difficulty = json.difficulty;
                args.tx_per_block = json.tx_per_block;
                args.reward = json.reward;
                args.halving = json.halving;
                args.fee = json.fee;
            }
            None => {
                eprintln!("[#] ARGS:SYNC - get mutable reference failed");
                return Err(SyncError::InvalidValue);
            }
        };
    }
    Ok(SyncState::Ready)
}

/// Synchroniye the coinbase address.
/// Returns `SyncState::Ready` if the synchronization succeeds.
pub fn sync_coinbase(addr: &str) -> Result<SyncState, SyncError> {
    // craft request
    let req = Request {
        dtype: Dtype::GetCoinbaseAddress,
        data: "",
        addr: addr.to_string(),
    };
    // send request
    let stream = match request(addr, &req) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] COINBASE:SYNC - request list of peers error: {}", e);
            return Err(SyncError::Request);
        }
    };
    // receive list of peers
    let response: Response<String> = match receive(stream) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] COINBASE:SYNC - receive list of peers error: {}", e);
            return Err(SyncError::Receive);
        }
    };
    // set coinbase address
    COINBASE.get_or_init(|| response.res);
    Ok(SyncState::Ready)
}

/// Synchronize the list of peers by requesting peers and broadcasting it's own address.
/// Returns `SyncState::Ready` if the synchronization succeeds.
pub fn sync_peers(
    addr: &str,
    addr_self: &str,
    peers: &Arc<Mutex<Vec<String>>>,
) -> Result<SyncState, SyncError> {
    println!("[+] PEERS:SYNC - updating list of peers");

    // craft request
    let req = Request {
        dtype: Dtype::GetPeers,
        data: "",
        addr: addr_self.to_string(),
    };
    // send request
    let stream = match request(addr, &req) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] PEERS:SYNC - request list of peers error: {}", e);
            return Err(SyncError::Request);
        }
    };
    // receive list of peers
    let response: Response<Vec<String>> = match receive(stream) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] PEERS:SYNC - receive list of peers error: {}", e);
            return Err(SyncError::Receive);
        }
    };
    let mut peers_rcved = response.res;

    // check peers
    let mut rm: Vec<String> = Vec::new();
    for peer in &peers_rcved {
        if !check_ip(&peer) {
            rm.push(peer.to_owned());
        }
    }
    // log
    if rm.len() > 0 {
        println!("[!] PEERS:SYNC - peers removed: {}", rm.len());
    }
    // remove invalid peers
    peers_rcved = subtract_vec(peers_rcved, rm);
    peers_rcved.push(addr.to_string()); // add entry node

    // broadcast address to peers
    println!("[+] PEERS:SYNC - broadcasting address");
    let (_, rm) = broadcast::<AddPeerResponse>(&peers_rcved, Dtype::AddPeer, &addr_self);

    // remove unreachable peers & update peers
    let mut peers = peers.lock().unwrap();
    *peers = subtract_vec(peers_rcved, rm); // update peers
    println!("[+] PEERS:SYNC - update list of peers successful");
    Ok(SyncState::Ready)
}

/// Returns the current timestamp.
pub fn timestamp_now() -> i64 {
    Utc::now().timestamp()
}
