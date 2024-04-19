use crate::{blockchain::*, comm::*};
use chrono::Utc;
use num_bigint::BigUint;
use regex::Regex;
use sha2::{Digest, Sha256};

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
pub enum PoolError {
    DuplicatedTransaction,
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

// TODO: make the chain resynchronize by a node where most equal hashes are
/// Check if blockchain has to be resynced.
/// Returns `false` if chain has to be resynced, otherwise `true`
pub fn check_chain(latest_block: &Block, peers: &Vec<String>) -> bool {
    let mut correct: u32 = 0;
    let (responses, _) = broadcast::<String>(peers, Dtype::GetLatestBlock, &String::new());

    for i in &responses {
        // compare hashes
        println!("DEBUG - check_chain received: {:?}", i);
    }

    // return result
    if correct >= responses.len().try_into().unwrap() {
        return true;
    } else {
        return false;
    }
}

/// Returns the target value.
pub fn get_difficulty(difficulty: u8) -> BigUint {
    // get hash difficulty
    let pat = "F".repeat(usize::from(difficulty));
    let to = "0".repeat(usize::from(difficulty));
    let hex_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        .replacen(&pat, &to, 1);
    BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap()
}

/// Returns the SHA256 hash of a byte array.
pub fn hash_str(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Recursive function that hashes all strings of a vector in pairs together to one hash using SHA256.
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
        Ok(output[0].clone()) // return output
    } else {
        Err(())
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

/// Returns the current timestamp.
pub fn timestamp_now() -> i64 {
    Utc::now().timestamp()
}
