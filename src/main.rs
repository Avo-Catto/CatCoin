use crate::src::{merkle_hash, Block, BlockChain, Transaction, TransactionPool};

mod src;
pub mod errors;

fn test() {
    // transaction values
    println!("\n\nTransaction:\n\n");

    let src: &str = "avo-catto";
    let dst: &str = "anyone else";
    let date: &str = "today";
    let mut val: f64 = 0.3;
    let broadcast: bool = false;

    // create transaction
    let transaction = Transaction::new(src, dst, date, val, broadcast);
    val = 1.0;
    let transaction2 = Transaction::new(src, dst, date, val, broadcast);
    println!("{}", transaction.str());
    
    // cast transaction to json
    let transaction_json: serde_json::Value = transaction.as_json();
    println!("Source: {:?}", transaction_json.get("src"));
    
    // cast json to transaction
    let transaction_copy = Transaction::from_json(transaction_json);
    println!("{}", transaction_copy.str());


    // transaction pool
    println!("\n\nTransactionPool:\n\n");

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


    // block
    println!("\n\nBlock:\n\n");

    let mut block = Block::new(0, [transaction.clone(), transaction2.clone()].to_vec(), "avocado".to_string());
    
    println!("block.hash: {}", block.calc_hash(0));
    println!("block.nonce: {}", block.nonce);

    // print block
    println!("{}", block.str());

    // block serialization / deserialization
    let block_json = block.as_json();
    println!("{:#?}", block_json);
    
    let block_copy = Block::from_json(block_json);
    println!("{}", block_copy.str());


    // blockchain
    println!("\n\nBlockchain:\n\n");
    
    let mut new_block = Block::new(0, Vec::new(), "genisis block".to_string());
    println!("Hash: {}", new_block.calc_hash(2));
    println!("Block:\n{}", new_block.str());

    let mut block_chain = BlockChain::new_with_genisis();
    let _ = block_chain.add_block(&new_block);

    for i in block_chain.get_chain() {
        println!("Hash of block in chain: {}", i.hash);
    }

    println!("last block: {}", block_chain.get_latest().hash);

    let new_chain = [block, new_block];

    block_chain.set_chain(new_chain.to_vec());

    for i in block_chain.get_chain() {
        println!("Hash of block in chain: {}", i.hash);
    }

    println!("{}", block_chain.str());

    println!("\n\nExecution succeed\n\n");

}


fn main() {
    test();
}
