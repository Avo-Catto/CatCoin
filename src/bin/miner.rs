use std::{env, process::exit};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::json;
use CatCoin::{get_difficulty, Block};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Debug, Deserialize)]
struct Receiver {
    start: u64,
    steps: u64,
    difficulty: u8,
    block: serde_json::Value,
}

fn hash_block(target_val: BigUint, block: &mut Block, mut start: u64, steps: u64) {
    let mut val = get_difficulty(0); // enter loop
    while val > target_val {
        // calculate hash and get value
        val = BigUint::parse_bytes(block.calc_hash(start).as_bytes(), 16).unwrap();
        start += steps;
    }
}

fn main() { // TODO: error handling
    let args: Vec<String> = env::args().collect(); // collect args
    let decoded = STANDARD.decode(&args[1]).unwrap(); // decode base64
    let json_string = String::from_utf8(decoded).unwrap(); // parse to string
    let json: Receiver = serde_json::from_str(&json_string).unwrap(); // deserialize to json

    // hash block
    let mut block = match Block::from_json(&json.block) {
        Ok(n) => n,
        Err(e) => {
            eprint!("{:?}", e);
            exit(1);
        }
    };

    // hash block and return encoded json string
    hash_block(get_difficulty(json.difficulty), &mut block, json.start, json.steps); // hash block
    let json = json!({"nonce": &block.nonce, "hash": &block.hash}); // format json string
    let encoded = STANDARD.encode(format!("{}", json)); // encode using base64
    print!("{}", encoded); // return data
    exit(0);
}
