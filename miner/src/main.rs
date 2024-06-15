extern crate base64;
extern crate node;
extern crate num_bigint;
extern crate serde;
extern crate serde_json;
use base64::{engine::general_purpose::STANDARD, Engine};
use node::utils::{difficulty_from_u8, hash_str};
use num_bigint::BigUint;
use serde::Deserialize;
use std::{
    env,
    io::{stderr, stdin, stdout, Write},
    process::exit,
    thread,
};

#[derive(Debug, Deserialize)]
struct Receiver {
    hash_data: String,
    difficulty: u8,
    start: u64,
}

/// Mine the given block.
fn mine(target_val: BigUint, hash_data: &str, mut start: u64) -> u64 {
    let check_skip = thread::spawn(|| match stdin().read_line(&mut String::new()) {
        Ok(_) => (),
        Err(e) => eprintln!(
            "[#] MINERBIN - skip current block read stdin error: {:?}",
            e
        ),
    });
    // enter loop
    loop {
        // check if skipped
        if check_skip.is_finished() {
            exit(0);
        }
        // calculate hash and get value
        let hash = hash_str(format!("{}${}", hash_data, start).as_bytes());
        let val = match BigUint::parse_bytes(hash.as_bytes(), 16) {
            Some(n) => n,
            None => {
                let _ = stderr().write_all(b"[#] MINERBIN - parse hash to value error");
                exit(1);
            }
        };
        // check value
        if val <= target_val {
            break;
        }
        // check if nonce exeeds data type
        if start == u64::MAX {
            start = 0
        } else {
            start += 1;
        }
    }
    start
}

fn main() {
    let args: Vec<String> = env::args().collect(); // collect args
    let decoded = STANDARD.decode(&args[1]).unwrap(); // decode base64

    // deserialize to json
    let json: Receiver = match serde_json::from_slice(&decoded) {
        Ok(n) => n,
        Err(e) => {
            let _ =
                stderr().write_all(format!("[#] MINERBIN - parse to json error: {}", e).as_bytes());
            exit(1);
        }
    };
    // hash block
    let nonce = mine(
        difficulty_from_u8(json.difficulty),
        &json.hash_data,
        json.start,
    );
    // serialize output
    match stdout().write_all(&nonce.to_be_bytes()) {
        Ok(_) => (),
        Err(e) => {
            let _ = stderr().write_all(
                format!(
                    "[#] MINERBING - write encoded output into stdout error: {}",
                    e
                )
                .as_bytes(),
            );
        }
    };
    exit(0);
}
