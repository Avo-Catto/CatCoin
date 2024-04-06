use base64::{engine::general_purpose::STANDARD, Engine};
use cat_coin::{get_difficulty, Block};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::json;
use std::{env, io::stdin, process::exit, thread};

#[derive(Debug, Deserialize)]
struct Receiver {
    start: u64,
    difficulty: u8,
    block: serde_json::Value,
}

fn hash_block(target_val: BigUint, block: &mut Block, mut start: u64) {
    let check_skip = thread::spawn(|| match stdin().read_line(&mut String::new()) {
        Ok(_) => (), // eprintln!("DEBUG[MINERBIN] - skip block"), // DEBUG
        Err(e) => eprintln!(
            "[#] MINERBIN - skip current block read stdin error: {:?}",
            e
        ),
    });

    // enter loop
    let mut val = get_difficulty(0);
    while val > target_val {
        // check if skipped
        if check_skip.is_finished() {
            exit(0);
        }

        // calculate hash and get value
        val = BigUint::parse_bytes(block.calc_hash(start).as_bytes(), 16).unwrap();
        start += 1;
        // TODO: if nonce exeeds data type, continue at 0
        // TODO: and find a way to transfer this huge number using max u64 data type
        // maybe modulo or something...
    }
}

fn main() {
    // TODO: error handling
    let args: Vec<String> = env::args().collect(); // collect args
    let decoded = STANDARD.decode(&args[1]).unwrap(); // decode base64
    let json_string = String::from_utf8(decoded).unwrap(); // parse to string
    let json: Receiver = serde_json::from_str(&json_string).unwrap(); // deserialize to json

    // construct block from json
    let mut block = match Block::from_json(&json.block) {
        Ok(n) => n,
        Err(e) => {
            eprint!("{:?}", e);
            exit(1);
        }
    };

    // hash block
    hash_block(get_difficulty(json.difficulty), &mut block, json.start);

    // serialize output
    let json = json!({"nonce": &block.nonce, "merkle": &block.merkle, "hash": &block.hash}); // format json string
    let encoded = STANDARD.encode(format!("{}", json)); // encode using base64
    print!("{}", encoded); // return data
    exit(0);
}
