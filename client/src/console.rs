extern crate aes_gcm;
extern crate openssl;
extern crate rpassword;
extern crate sha2;
extern crate uuid;
use self::rpassword::prompt_password;
use self::sha2::{Digest, Sha256};
use crate::wallet::{gen_address, Transaction, Wallet};
use crate::{wallet::check_wallet_exists, KEY_PATH, USER_PATH, WALLET_PATH};
use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    str::FromStr,
};
use uuid::Uuid;

#[derive(Debug)]
pub struct User {
    pub username: String,
    pub password: String,
    pub id: Uuid,
    pub wallet: Wallet,
}

/// Append a line to a file.
fn append_line(path: &str, data: &str) -> Result<(), io::Error> {
    // open file
    let mut file = match fs::File::options().write(true).append(true).open(path) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match file.write_all(format!("{}\n", data).as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Returns new anonymous user.
pub fn become_anonymous() -> User {
    User {
        username: String::from("anonymous"),
        password: String::from(""),
        id: Uuid::new_v4(),
        wallet: Wallet::placeholder(),
    }
}

/// Get all users from lines.
pub fn get_users_from_lines(lines: Vec<String>) -> Vec<User> {
    lines
        .iter()
        .map(|x| {
            let y: Vec<String> = x.split(':').map(|z| z.to_string()).collect();
            if y.len() == 3 {
                User {
                    username: y[0].clone(),
                    password: y[2].clone(),
                    id: Uuid::from_str(&y[1]).expect(" [#]  invalid uuid format"),
                    wallet: Wallet::placeholder(),
                }
            } else {
                // avoid error
                User {
                    username: String::new(),
                    password: String::new(),
                    id: Uuid::new_v4(),
                    wallet: Wallet::placeholder(),
                }
            }
        })
        .collect()
}

/// Log into account and return user instance.
pub fn login() -> Result<User, io::Error> {
    let username = prompt("username: ").concat().to_string();
    let password = prompt_password(" [~]> password: ").unwrap();

    // get users
    let lines = match read_lines(USER_PATH) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    let users = get_users_from_lines(lines);

    // find user and check password
    let user = match users.iter().find(|x| x.username == username) {
        Some(n) => n,
        None => return Err(io::Error::other("user not found")),
    };

    // return user / error
    if user.password == format!("{:x}", Sha256::digest(password)) {
        // load wallet
        let wallet = if check_wallet_exists(user.id) {
            match Wallet::from(user.id, &user.password) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!(" [#] BACKEND:login - wallet from uid error: {}", e);
                    Wallet::placeholder()
                }
            }
        } else {
            Wallet::placeholder()
        };
        // construct & return User
        Ok(User {
            username: user.username.clone(),
            password: user.password.clone(),
            id: user.id,
            wallet,
        })
    } else {
        Err(io::Error::other("invalid password"))
    }
}

/// Create a new transaction.
pub fn new_transaction(wallet: &Wallet) -> Result<Transaction, Box<dyn Error>> {
    // source
    let idx = match prompt("source (index of address): ").first() {
        Some(n) => match n.parse() {
            Ok(m) => m,
            Err(e) => {
                eprintln!(" [#] BACKEND:new_transaction - parse index error: {}", e);
                return Err(Box::new(e));
            }
        },
        None => {
            eprintln!(" [#] BACKEND:new_transaction - no index error");
            return Err("no index error".into());
        }
    };
    // check index
    if idx > wallet.idx_addr {
        output(" [#] BACKEND:new_transaction - invalid index error");
        return Err("invalid index error - address doesn not exist now".into());
    }
    // get corresponding salt or generate new address
    let salt = match wallet.addr_salts.get(idx as usize) {
        Some(n) => n,
        None => {
            output(" [#] BACKEND:new_transaction - retrieve salt error");
            return Err("retrieve salt error".into());
        }
    };
    // generate address
    let src = gen_address(&wallet.pub_key, idx, salt);

    // destination
    let dst = prompt("destination: ");
    if dst.len() < 1 {
        eprintln!(" [#] BACKEND:new_transaction - no destination specified");
        return Err("input doesn't match required length".into());
    }
    // value
    let val = prompt("amount: ");
    if val.len() < 1 {
        eprintln!(" [#] backend:new_transaction - no value specified");
        return Err("input doesn't match required length".into());
    }
    let val = match val[0].parse::<f64>() {
        Ok(n) => n,
        Err(e) => {
            eprintln!(" [#] BACKEND:new_transaction - parse value error: {}", e);
            return Err(Box::new(e));
        }
    };
    // valid after
    let after = prompt("valid after (e.g. xm:xh:xd:xw):");
    let after = if after.len() < 1 { "" } else { &after[0] };

    // construct transaction
    match Transaction::new(&src, &dst[0], val, after) {
        Ok(n) => Ok(n),
        Err(e) => Err(e),
    }
}

/// Create a new user and return the username.
pub fn new_user() -> Result<String, io::Error> {
    let username = prompt("username: ").concat().to_string();
    let password = prompt_password(" [~]> password: ").unwrap();
    let id = Uuid::new_v4();

    // get users
    let lines = match read_lines(USER_PATH) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    let users = get_users_from_lines(lines);

    // check if user already exists
    if users.iter().any(|x| x.username == username) {
        return Err(io::Error::other("user exists"));
    };
    // save user in file
    match append_line(
        USER_PATH,
        &format!(
            "{}:{}:{:x}",
            username,
            id.to_string(),
            Sha256::digest(password.as_bytes())
        ),
    ) {
        Ok(_) => Ok(username),
        Err(e) => Err(e),
    }
}

/// Output some stuff in a fancy format.
pub fn output(text: &str) {
    for i in text.split('\n') {
        println!(" [+]  {}", i);
    }
}

/// Output some stuff with a fancy frame.
pub fn output_framed(text: &str) {
    println!(
        "\n [+]>{:-<30}<[+]\n  V{:<34}V \n  |{:^34}|\n  A{:<34}A \n [+]>{:-<30}<[+]\n",
        "", "", text, "", ""
    );
}

/// Prompt the user for input.
pub fn prompt(t: &str) -> Vec<String> {
    // prompt
    if t.ends_with("\n") {
        print!(" [+]  {} [~]> ", t);
    } else {
        print!(" [~]> {}", t);
    }
    let _ = io::stdout().flush();

    // get input
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);

    // into vector of single words
    let out: Vec<&str> = input.split_whitespace().collect();
    let out: Vec<String> = out.iter().map(|x| x.to_string()).collect();
    out
}

/// Read the lines of a file.
fn read_lines(path: &str) -> Result<Vec<String>, io::Error> {
    // open file
    let mut file = match fs::File::open(path) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    // read file
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf);

    // split lines
    let buf: Vec<&str> = buf.split('\n').collect();
    Ok(buf.iter().map(|x| x.to_string()).collect())
}

/// Set up the file structure.
pub fn setup() {
    match fs::create_dir_all(KEY_PATH) {
        Ok(_) => (),
        Err(e) => {
            eprintln!(" [#] SETUP - create KEY_PATH error: {}", e);
        }
    }
    match fs::create_dir_all(WALLET_PATH) {
        Ok(_) => (),
        Err(e) => {
            eprintln!(" [#] SETUP - create WALLET_PATH error: {}", e);
        }
    }
    match fs::File::open(USER_PATH) {
        Ok(_) => (),
        Err(_) => {
            match fs::File::create_new(USER_PATH) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!(" [#] SETUP - create USER_PATH error: {}", e);
                }
            };
        }
    }
}
