use crate::src::{Transaction, TransactionPool};

mod src;

fn main() {
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
    if pool.add(&transaction) { println!("added! {:?}", transaction.as_json()["val"]) }
    else { println!("not added! {:?}", transaction.as_json()["val"]) }
    
    if pool.add(&transaction2) { println!("added! {:?}", transaction.as_json()["val"]) }
    else { println!("not added! {:?}", transaction2.as_json()["val"]) }

    if pool.add(&transaction_copy) { println!("added! {:?}", transaction.as_json()["val"]) }
    else { println!("not added! {:?}", transaction_copy.as_json()["val"]) }

    // print pool
    println!("\n{}", pool.str());

    // flush pool
    pool.flush();
    println!("\n{}", pool.str());

}
