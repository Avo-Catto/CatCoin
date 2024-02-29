use crate::src::{merkle_hash, Transaction, TransactionPool};

mod src;
pub mod errors;

fn test() {
    // transaction values
    let src: &str = "avo-catto";
    let dst: &str = "anyone else";
    let date: &str = "today";
    let mut val: f64 = 0.3;
    let broadcast: bool = false;

    // create transaction
    let transaction = src::Transaction::new(src, dst, date, val, broadcast);
    val = 1.0;
    let transaction2 = src::Transaction::new(src, dst, date, val, broadcast);
    println!("{}", transaction.str());
    
    // cast transaction to json
    let transaction_json: serde_json::Value = transaction.as_json();
    println!("Source: {:?}", transaction_json.get("src"));
    
    // cast json to transaction
    let transaction_copy = Transaction::from_json(transaction_json);
    println!("{}", transaction_copy.str());

    // transaction pool
    let mut pool = TransactionPool::new();

    // add original transaction
    match pool.add(&transaction) { 
        Ok(()) => println!("added! {:?}", transaction.as_json()["val"]),
        Err(_) => println!("not added! {:?}", transaction.as_json()["val"]),
    }
    
    match pool.add(&transaction2) {
        Ok(()) => println!("added! {:?}", transaction.as_json()["val"]),
        Err(_) => println!("not added! {:?}", transaction2.as_json()["val"]),
    }

    match pool.add(&transaction_copy) {
        Ok(()) => println!("added! {:?}", transaction.as_json()["val"]),
        Err(_) => println!("not added! {:?}", transaction_copy.as_json()["val"]),
    }

    // print pool
    println!("\n{}", pool.str());

    // flush pool
    pool.flush();
    println!("\n{}", pool.str());

    // merkle hash
    let hash_list: [String; 4] = ["Hello world".to_string(), "avocado".to_string(), "abcd".to_string(), "ahhhhh".to_string()];
    println!("{:?}", merkle_hash(hash_list.to_vec()).unwrap());
}


fn main() {
    test();
}
