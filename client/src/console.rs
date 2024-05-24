use crate::{wallet::check_wallet_exists, KEY_PATH, USER_PATH, WALLET_PATH};
use std::{
    fs,
    io::{self, Read, Write},
    str::FromStr,
};

extern crate openssl;
extern crate uuid;
use uuid::Uuid;
extern crate sha2;
use self::sha2::{Digest, Sha256};
use crate::wallet::Wallet;

extern crate aes_gcm;

#[derive(Debug)]
pub struct User {
    pub username: String,
    pub password: String,
    pub id: Uuid,
    pub wallet: Wallet,
}

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

pub fn output_framed(text: &str) {
    println!(
        "\n [+]>{:-<30}<[+]\n  V{:<34}V \n  |{:^34}|\n  A{:<34}A \n [+]>{:-<30}<[+]\n",
        "", "", text, "", ""
    );
}

pub fn output(text: &str) {
    for i in text.split('\n') {
        println!(" [+]  {}", i);
    }
}

pub fn setup() {
    match fs::create_dir_all(KEY_PATH) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("DEBUG - create KEY_PATH error: {}", e);
        }
    }
    match fs::create_dir_all(WALLET_PATH) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("DEBUG - create WALLET_PATH error: {}", e);
        }
    }
    match fs::File::open(USER_PATH) {
        Ok(_) => (),
        Err(_) => {
            match fs::File::create_new(USER_PATH) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("DEBUG - create USER_PATH error: {}", e);
                }
            };
        }
    }
}

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

pub fn login() -> Result<User, io::Error> {
    let username = prompt("username: ").concat().to_string();
    let password = prompt("password: ").concat().to_string();

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
            println!("DEBUG - real wallet");
            match Wallet::from(user.id, &user.password) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("BACKEND:login - wallet from uid error: {}", e);
                    Wallet::placeholder()
                }
            }
        } else {
            println!("DEBUG - placeholder wallet");
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

pub fn become_anonymous() -> User {
    User {
        username: String::from("anonymous"),
        password: String::from(""),
        id: Uuid::new_v4(),
        wallet: Wallet::placeholder(),
    }
}

pub fn new_user() -> Result<String, io::Error> {
    let username = prompt("username: ").concat().to_string();
    let password = prompt("password: ").concat().to_string();
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
