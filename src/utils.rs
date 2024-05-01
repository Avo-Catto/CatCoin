use crate::blockchain::BlockChain;
use crate::comm::*;
use chrono::Utc;
use num_bigint::BigUint;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub enum BlockError {
    TransactionValidationFailed,
    MismatchPreviousHash,
    MismatchHash,
    MismatchMerkleHash,
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

#[derive(Debug)]
pub enum SyncState {
    Fine,
    Needed,
    Ready,
    Running,
}

#[derive(Debug)]
pub enum TransactionValidationError {
    MismatchSource,
    MismatchDestination,
    MismatchHash,
}
pub type TVE = TransactionValidationError;

/// Performs a regex check for an address.
/// Example: 127.0.0.1:8080 - valid
pub fn check_addr(addr: &String) -> bool {
    let addr_re = Regex::new(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})$"
    ).unwrap();
    addr_re.is_match(addr)
}

// TODO: write this function
// Check if node needs to synchronize.
pub fn check_sync(peers: &Vec<String>, chain: &BlockChain) -> Result<SyncState, ()> {
    // check blockchain
    let map = collect_map(peers, Dtype::GetBlock, "-1");
    let latest_hash = match get_key_by_vec_len(map.clone()) {
        Some(n) => n,
        None => return Err(()),
    };

    Ok(SyncState::Fine)
}

/// Performs a regex check for a SHA256 hash.
pub fn check_sha256(hash_str: &String) -> bool {
    let sha256_re = Regex::new("^[a-fA-F0-9]{64}$").unwrap();
    sha256_re.is_match(hash_str)
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

/// Synchronize the difficulty.
/// Returns `SyncState::Ready` if the synchronization succeeds.
pub fn sync_difficulty(addr: &str, difficulty: &Arc<Mutex<u8>>) -> Result<SyncState, SyncError> {
    println!("[+] DIFFICULTY:SYNC - updating difficulty");

    // craft request
    let req = Request {
        dtype: Dtype::GetDifficulty,
        data: "",
    };
    // connect to node
    let stream = match request(addr, &req) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] DIFFICULTY:SYNC - request difficulty error: {}", e);
            return Err(SyncError::Request);
        }
    };
    // receive difficulty
    let response: Response<u8> = match receive(stream) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] DIFFICULTY:SYNC - receive difficulty error: {}", e);
            return Err(SyncError::Receive);
        }
    };
    // check difficulty
    if response.res < 1 || response.res > 71 {
        eprintln!("[#] DIFFICULTY:SYNC - invalid difficulty");
        return Err(SyncError::InvalidValue);
    }
    // update difficulty
    *difficulty.lock().unwrap() = response.res;
    println!("[+] DIFFICULTY:SYNC - update difficulty successful");
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
        if !check_addr(&peer) {
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
