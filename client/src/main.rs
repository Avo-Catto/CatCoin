mod console;
mod wallet;
extern crate node;
extern crate uuid;
use std::{sync::OnceLock, usize};

use console::*;
use node::comm::{receive, request, AddTransactionResponse, Dtype, Request};
use wallet::{check_wallet_exists, gen_address, gen_salt, request_fee, Wallet};

const USER_PATH: &'static str = "client/data/passwd";
const KEY_PATH: &'static str = "client/data/keys";
const WALLET_PATH: &'static str = "client/data/wallets";
static mut ADDRESS: OnceLock<&str> = OnceLock::new();
static mut FEE: OnceLock<u8> = OnceLock::new();

fn help() {
    output(
        "new -> address / transaction / user / wallet
whoami 
login 
logout 
list -> addresses
set -> node",
    );
}

fn main() {
    unsafe {
        ADDRESS.get_or_init(|| "127.0.0.1:8000");
        FEE.get_or_init(|| match request_fee() {
            Ok(n) => match n {
                Some(m) => m,
                None => {
                    output("couldn't retrieve fee, use default instead: 5%");
                    5
                }
            },
            Err(e) => {
                output(&format!(
                    "retrieve fee error: {}\nuse default instead: 5%",
                    e
                ));
                5
            }
        });
    }
    setup();
    let mut user = become_anonymous();
    loop {
        // get command
        let cmd = prompt("");
        if cmd.is_empty() {
            continue;
        }
        // process input
        // TODO: exit
        match cmd[0].as_str() {
            "help" => help(),
            "new" => {
                if cmd.len() < 2 {
                    continue;
                }
                match cmd[1].as_str() {
                    "user" => {
                        match new_user() {
                            Ok(n) => output(&format!("created new user: {}", n)),
                            Err(e) => output(&format!("create user error: {}", e)),
                        };
                    }
                    // TODO: could it be possible that the wallet isn't correctly overwritten which
                    //       lead to the decryption error?
                    "wallet" => {
                        // check if logged in
                        if user.username == "anonymous" {
                            output("you have to be logged in to create a wallet");
                            continue;
                        }
                        // check if already wallet
                        if check_wallet_exists(user.id) {
                            output("You are about to overwrite your current wallet,");
                            let answer = prompt("are you sure you want to proceed? [y/n]\n");
                            if answer.len() == 0 {
                                output("creating new wallet stopped");
                                continue;
                            }
                            if answer[0] != "y" {
                                output("creating new wallet stopped");
                                continue;
                            }
                        }
                        // proceed with creation
                        output("creating new wallet proceed");
                        let mnemonics = prompt("write some mnemonics:\n");
                        let wallet = match Wallet::new(mnemonics, user.id, &user.password) {
                            Ok(n) => n,
                            Err(e) => {
                                output(&format!("create wallet error: {}", e));
                                continue;
                            }
                        };
                        user.wallet = wallet;
                    }
                    "address" => {
                        // check if wallet is placeholder
                        if user.wallet.placeholder {
                            output("no wallet initialized yet");
                            continue;
                        }
                        // set index
                        let idx = if cmd.len() > 2 {
                            match cmd[2].parse() {
                                Ok(n) => n,
                                Err(e) => {
                                    output(&format!("invalid index: {}", e));
                                    continue;
                                }
                            }
                        } else {
                            user.wallet.idx_addr
                        };
                        // get salt
                        let mut salt = if idx < user.wallet.idx_addr {
                            match user.wallet.addr_salts.get(idx as usize) {
                                Some(n) => String::from(n),
                                None => {
                                    output(&format!("salt index error"));
                                    continue;
                                }
                            }
                        } else {
                            // generate salt & save it
                            let salt = gen_salt(4);
                            user.wallet.addr_salts.push(salt.clone());
                            user.wallet.idx_addr += 1;
                            salt
                        };

                        // generate address
                        let addr = loop {
                            // ensures the address isn't too short
                            let addr = gen_address(&user.wallet.pub_key, idx, &salt);
                            if addr.as_bytes().len() > 46 {
                                break addr;
                            }
                            salt = gen_salt(4);
                        };
                        output(&format!("IDX: {} > {}", idx, addr));

                        // save wallet
                        match user.wallet.save(&user.password) {
                            Ok(_) => (),
                            Err(e) => eprintln!("save changes error: {}", e),
                        };
                    }
                    "transaction" => {
                        // check if wallet is placeholder
                        if user.wallet.placeholder {
                            output("no wallet initialized yet");
                            continue;
                        }
                        // list addresses
                        output("");
                        for i in 0..(user.wallet.idx_addr) {
                            output(&format!(
                                "IDX: {} > {}",
                                i,
                                gen_address(
                                    &user.wallet.pub_key,
                                    i,
                                    &user.wallet.addr_salts[i as usize]
                                )
                            ));
                        }
                        output("");

                        // create transaction
                        let mut transaction = match new_transaction(&user.wallet) {
                            Ok(n) => n,
                            Err(e) => {
                                output(&format!("transaction error: {}", e));
                                continue;
                            }
                        };
                        // sign transaction
                        match transaction.sign(&user.wallet) {
                            Ok(_) => (),
                            Err(e) => {
                                output(&format!("sign transaction error: {}", e));
                                continue;
                            }
                        };
                        // validate transaction
                        match transaction.validate() {
                            Ok(_) => (),
                            Err(e) => {
                                output(&format!("transaction validation error: {:?}", e));
                                continue;
                            }
                        }
                        // TODO: better formatting and show fee
                        output(&format!("\n<> Transaction <>\n{}\n", transaction));
                        output("Please double check the information before releasing.");
                        if prompt("Are you sure you want to release the transaction? [y/n]")[0]
                            .to_lowercase()
                            != "y"
                        {
                            output("new transaction aborted");
                            continue;
                        }
                        // craft request
                        let req = Request {
                            dtype: Dtype::AddTransaction,
                            data: transaction.as_json().to_string(),
                            addr: String::new(),
                        };
                        // send transaction into network
                        let stream = match request(unsafe { ADDRESS.get().unwrap() }, &req) {
                            Ok(n) => n,
                            Err(e) => {
                                output(&format!("transaction aborted due to error: {}", e));
                                continue;
                            }
                        };
                        // receive response
                        match receive::<AddTransactionResponse>(stream) {
                            Ok(n) => output(&format!("transaction released: {:?}", n.res)),
                            Err(e) => output(&format!("transaction aborted due to error: {}", e)),
                        };
                    }
                    _ => (),
                }
            }
            "login" => match login() {
                Ok(n) => {
                    output_framed(&format!("Welcome {}!", n.username));
                    user = n;
                }
                Err(e) => output(&format!("login error: {}", e)),
            },
            "logout" => {
                // save changes
                match user.wallet.save(&user.password) {
                    Ok(_) => (),
                    Err(e) => output(&format!("WARNING - saving wallet error: {}", e)),
                }
                // update user
                user = become_anonymous();
            }
            "list" => {
                // check if wallet is placeholder
                if user.wallet.placeholder {
                    output("no wallet initialized yet");
                    continue;
                }
                if cmd.len() < 2 {
                    continue;
                }
                match cmd[1].as_str() {
                    "addresses" => {
                        // check if wallet is placeholder
                        if user.wallet.placeholder {
                            output("no wallet initialized yet");
                            continue;
                        }
                        // list addresses
                        for i in 0..(user.wallet.idx_addr) {
                            output(&format!(
                                "IDX: {} > {}",
                                i,
                                gen_address(
                                    &user.wallet.pub_key,
                                    i,
                                    &match user.wallet.addr_salts.get(i as usize) {
                                        Some(n) => n.to_string(),
                                        None => {
                                            eprint!("None at index: {}", i);
                                            return;
                                        }
                                    }
                                )
                            ));
                        }
                    }
                    _ => (),
                }
            }
            "set" => {
                if cmd.len() < 2 {
                    continue;
                }
                match cmd[1].as_str() {
                    "node" => output("set the ip address of the node in future"), // TODO
                    _ => (),
                }
            }
            "whoami" => output(&user.username),
            _ => continue,
        }
    }
}

// MINDSET: you write quality code, not quick and bad code!
// > FIXME: the salt is read wrong for validation of the transaction
// > TODO: make the address shorter
// TODO: one error logging
// TODO: balance + don't forget about the delay
// TODO: improve user experience
