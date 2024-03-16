use std::env;
// use num_bigint::BigUint;
// use crate::src::Block;

fn test_miner() {
    let args = env::args_os();
    println!("{:?}", args);

    std::process::exit(1);
    
    // initial hash
    /* let mut i = 0;
    let mut val = BigUint::parse_bytes(block.calc_hash(i).as_bytes(), 16).unwrap();

    while val > target_val {
        val = BigUint::parse_bytes(block.calc_hash(i).as_bytes(), 16).unwrap();
        i += 1;
    } */
}

fn main() {
    println!("{:#?}", env::args_os());
}
