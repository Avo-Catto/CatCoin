extern crate uuid;
mod console;
mod wallet;

use console::*;
use wallet::{check_wallet_exists, Wallet};

const USER_PATH: &'static str = "client/data/passwd";
const KEY_PATH: &'static str = "client/data/keys";
const WALLET_PATH: &'static str = "client/data/wallets";

fn help() {}

fn main() {
    setup();
    let mut user = become_anonymous();
    loop {
        // get command
        let cmd = prompt("");
        if cmd.is_empty() {
            continue;
        }
        // process input
        match cmd[0].as_str() {
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
                        // check if logged in
                        if user.username == "anonymous" {
                            output("you have to be logged in to access a wallet");
                            continue;
                        }
                        // generate new address
                        let idx = if cmd.len() > 2 {
                            match cmd[2].parse() {
                                Ok(n) => n,
                                Err(e) => {
                                    output(&format!("invalid index: {}", e));
                                    continue;
                                }
                            }
                        } else {
                            user.wallet.idx_addr + 1
                        };
                        let addr = user.wallet.gen_address(idx);
                        output(&format!("IDX: {} > {}", idx, addr));
                    }
                    _ => output("account options"), // TODO
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
                // check if logged in
                if user.username == "anonymous" {
                    output("you have to be logged in to access a wallet");
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
                        for i in 0..(user.wallet.idx_addr + 1) {
                            output(&format!("IDX: {} > {}", i, user.wallet.gen_address(i)));
                        }
                    }
                    _ => output("list options"), // TODO
                }
            }
            "whoami" => output(&user.username),
            _ => continue,
        }
    }
}
