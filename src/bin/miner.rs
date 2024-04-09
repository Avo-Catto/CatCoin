use base64::{engine::general_purpose::STANDARD, Engine};
use cat_coin::{get_difficulty, Block};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::json;
use std::{env, io::stdin, process::exit, thread};

#[derive(Debug, Deserialize)]
struct Receiver {
    block: serde_json::Value,
    difficulty: u8,
    start: u64,
}

/// Mine the given block.
fn mine(target_val: BigUint, block: &mut Block, mut start: u64) {
    let check_skip = thread::spawn(|| match stdin().read_line(&mut String::new()) {
        Ok(_) => (),
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

        // check if nonce exeeds data type
        if start == u64::MAX {
            start = 0
        } else {
            start += 1;
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect(); // collect args
    let decoded = STANDARD.decode(&args[1]).unwrap(); // decode base64
    let json_string = match String::from_utf8(decoded) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[#] MINERBIN - string from bytes error: {}", e);
            exit(1);
        }
    };
    // deserialize to json
    let json: Receiver = serde_json::from_str(&json_string).unwrap();

    // construct block from json
    let mut block = match Block::from_json(&json.block) {
        Ok(n) => n,
        Err(e) => {
            eprint!("[#] MINERBIN - construct block from json error: {:?}", e);
            exit(1);
        }
    };

    // hash block
    mine(get_difficulty(json.difficulty), &mut block, json.start);

    // serialize output
    let json = json!({
        "hash": &block.hash,
        "merkle": &block.merkle,
        "nonce": &block.nonce,
    });
    let encoded = STANDARD.encode(format!("{}", json));
    print!("{}", encoded); // return data
    exit(0);
}
