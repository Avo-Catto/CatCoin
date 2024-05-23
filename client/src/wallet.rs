extern crate aes_gcm;
extern crate bs58;
extern crate chrono;
extern crate openssl;
extern crate rand;
extern crate rcgen;
extern crate serde;
extern crate serde_json;
extern crate sha2;

// use self::bs58;
use self::aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use self::chrono::Utc;
use self::openssl::{pkey::PKey, rsa::Rsa, sign::Signer, symm::Cipher};
use self::rand::{thread_rng, Rng};
use self::serde::{Deserialize, Serialize};
use self::serde_json::json;
use self::sha2::{Digest, Sha256, Sha512};
use crate::{KEY_PATH, WALLET_PATH};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::{error::Error, io};
use uuid::Uuid;

/// Returns the current timestamp.
pub fn timestamp_now() -> i64 {
    Utc::now().timestamp()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub src: String,
    pub dst: String,
    pub val: f64,
    pub timestamp: i64, // timestamp when the transaction will be valid
    pub signature: String,
    pub pub_key: Vec<u8>,
    pub broadcast: bool,
}

impl Transaction {
    // Constructor
    pub fn new(src: String, dst: String, val: f64, valid_after: String) -> Self {
        Transaction {
            src,
            dst,
            val,
            timestamp: timestamp_now(), // TODO: temporarily
            signature: String::new(),
            pub_key: Vec::new(),
            broadcast: true,
        }
    }

    pub fn sign(&self, wallet: Wallet) {
        sign
    }

    // TODO
    fn check_address() {}

    // TODO: check if wallet has enough coins
    fn check_value() {}

    // TODO
    fn valid_after_to_timestamp() {}
}

#[derive(Debug)]
pub struct Wallet {
    pub idx_addr: u32,
    passphrase: String,
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
    salt: String,
    uid: Uuid,
    pub placeholder: bool,
}

#[derive(Debug, Deserialize)]
pub struct WalletReader {
    pub idx_addr: u32,
    pub passphrase: String,
    pub salt: String,
}

// TODO: alphabetic order & docs
impl Wallet {
    // Constructor
    pub fn new(mnemonics: Vec<String>, uid: Uuid, password: &str) -> Result<Self, Box<dyn Error>> {
        // generate keypair
        let rsa = Rsa::generate(4096).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let cipher = Cipher::camellia_256_cbc();

        // passphrase
        let salt = Self::gen_salt();
        let passphrase = Self::get_passphrase(&mnemonics, &salt);

        // grep keys and do fancy stuff with it
        let pub_key = pkey.public_key_to_pem().unwrap();
        let priv_key = pkey
            .private_key_to_pem_pkcs8_passphrase(cipher, &passphrase.as_bytes())
            .unwrap();

        // construct
        let wallet = Wallet {
            passphrase,
            pub_key,
            priv_key,
            salt,
            idx_addr: 0,
            uid,
            placeholder: false,
        };
        // store keys
        let _ = wallet.save(password);
        Ok(wallet)
    }

    /// Construct a new wallet without any initializations unlike Self::new().
    pub fn placeholder() -> Self {
        Wallet {
            passphrase: String::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            salt: String::new(),
            idx_addr: 0,
            uid: Uuid::new_v4(),
            placeholder: true,
        }
    }

    pub fn from(uid: Uuid, password: &str) -> Result<Wallet, Box<dyn Error>> {
        // public key - read file
        let mut f = match File::open(format!("{}/pub_key_{}", KEY_PATH, uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - read public key file: {}", e);
                return Err(Box::new(e));
            }
        };
        // read key from file
        let mut pub_key = Vec::new();
        let _ = f.read_to_end(&mut pub_key);

        // decrypt key
        let pub_key = match decrypt(password, &pub_key) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - decrypt public key error: {}", e);
                return Err(Box::new(io::Error::other("decryption error")));
            }
        };
        // private key - read file
        let mut f = match File::open(format!("{}/priv_key_{}", KEY_PATH, uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - read private key file error: {}", e);
                return Err(Box::new(e));
            }
        };
        // read key from file
        let mut priv_key = Vec::new();
        let _ = f.read_to_end(&mut priv_key);

        // decrypt key
        let priv_key = match decrypt(password, &priv_key) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - decrypt private key error: {}", e);
                return Err(Box::new(io::Error::other("decryption error")));
            }
        };
        // wallet - read file
        let mut f = match File::open(format!("{}/{}", WALLET_PATH, uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - read wallet file error: {}", e);
                return Err(Box::new(e));
            }
        };
        // read wallet from file
        let mut wallet = Vec::new();
        let _ = f.read_to_end(&mut wallet);

        // decrypt key
        let data = match decrypt(password, &wallet) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - decrypt wallet error: {}", e);
                return Err(Box::new(io::Error::other("decryption error")));
            }
        };
        // parse to json
        let json: WalletReader = match serde_json::from_str(&String::from_utf8_lossy(&data)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - parse wallet to json error: {}", e);
                return Err(Box::new(e));
            }
        };

        // DEBUG
        println!("DEBUG - pub key size: {}", pub_key.len()); // DEBUG
        println!("DEBUG - priv key size: {}", priv_key.len()); // DEBUG

        Ok(Wallet {
            idx_addr: json.idx_addr,
            passphrase: json.passphrase,
            priv_key,
            pub_key,
            salt: json.salt,
            uid,
            placeholder: false,
        })
    }

    fn get_passphrase(mnemonics: &Vec<String>, salt: &String) -> String {
        let passphrase = format!("{}${}", mnemonics.concat(), salt);
        format!("{:x}", Sha256::digest(passphrase.as_bytes()))
    }

    /// Generate a salt.
    fn gen_salt() -> String {
        let mut out: Vec<String> = Vec::new();
        for _ in 0..12 {
            let i: u16 = Rng::gen(&mut thread_rng());
            let c = match char::from_u32(i as u32) {
                Some(n) => n,
                None => continue,
            };
            out.push(c.to_string());
        }
        out.concat()
    }

    pub fn save(&self, password: &str) -> Result<(), Box<dyn Error>> {
        // wallet
        let wallet = json!({
            "idx_addr": self.idx_addr,
            "passphrase": self.passphrase,
            "salt": self.salt,
            "uid": self.uid.to_string(),
        })
        .to_string();

        // encrypt data
        let data = match encrypt(password, &wallet) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - encrypt wallet error: {}", e);
                return Err(Box::new(io::Error::other("encryption error")));
            }
        };
        // create file
        let mut f = match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(format!("{}/{}", WALLET_PATH, self.uid))
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - create public key file error: {}", e);
                return Err(Box::new(e));
            }
        };
        // write credentials to file
        match f.write_all(&data) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] WALLET:save - write credentials error: {}", e);
                return Err(Box::new(e));
            }
        }
        // public key
        // parse bytes to string
        let pub_key_str = match String::from_utf8(self.pub_key.clone()) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - parse bytes to string error: {}", e);
                return Err(Box::new(e));
            }
        };
        // encrypt public key
        let data = match encrypt(password, &pub_key_str) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - encrypt public key error: {}", e);
                return Err(Box::new(io::Error::other("encryption error")));
            }
        };
        // create file
        let mut f = match File::create(format!("{}/pub_key_{}", KEY_PATH, self.uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - create public key file error: {}", e);
                return Err(Box::new(e));
            }
        };
        // write key to file
        match f.write_all(&data) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] WALLET:save - write public key error: {}", e);
                return Err(Box::new(e));
            }
        }
        // private key
        // parse bytes to string
        let priv_key_str = match String::from_utf8(self.priv_key.clone()) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - parse bytes to string error: {}", e);
                return Err(Box::new(e));
            }
        };
        // encrypt private key
        let data = match encrypt(password, &priv_key_str) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - encrypt public key error: {}", e);
                return Err(Box::new(io::Error::other("encryption error")));
            }
        };
        // create file
        let mut f = match File::create(format!("{}/priv_key_{}", KEY_PATH, self.uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save - create private key file: {}", e);
                return Err(Box::new(e));
            }
        };
        // write key to file
        match f.write_all(&data) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] WALLET:save - write private key error: {}", e);
                return Err(Box::new(e));
            }
        }
        Ok(())
    }

    /// Generate an address based on the index.
    pub fn gen_address(&mut self, idx: u32) -> String {
        // hash public key
        let a = Sha512::digest(self.pub_key.clone());
        let mut a = a.to_vec();

        // append unique & critical information
        a.append(&mut self.salt.as_bytes().to_vec());
        a.append(&mut self.passphrase.as_bytes().to_vec());
        a.append(&mut idx.to_be_bytes().to_vec());

        let b = Sha512::digest(a);
        let c = Sha256::digest(b);

        // calculate checksum
        let d = Sha256::digest(c);
        let mut checksum = d[0..8].to_vec();

        // append checksum
        let mut c = c.to_vec();
        c.append(&mut checksum);

        // encode address
        let f = bs58::encode(&c).into_string();

        // update amount of addresses
        if idx > self.idx_addr {
            self.idx_addr = idx;
        }
        f
    }
}

pub fn check_wallet_exists(uid: Uuid) -> bool {
    match fs::File::open(format!("{}/{}", WALLET_PATH, uid)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn encrypt(password: &str, data: &str) -> Result<Vec<u8>, aes_gcm::Error> {
    let p = Sha256::digest(password);
    let key = Key::<Aes256Gcm>::from_slice(&p);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);
    match cipher.encrypt(&nonce, data.as_bytes()) {
        Ok(n) => {
            let mut n = n;
            n.append(&mut nonce.to_vec());
            Ok(n)
        }
        Err(e) => Err(e),
    }
}

pub fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let p = Sha256::digest(password);
    let key = Key::<Aes256Gcm>::from_slice(&p);
    let (data, nonce) = data.split_at(data.len() - 12);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    match cipher.decrypt(&nonce, data) {
        Ok(n) => Ok(n),
        Err(e) => Err(e),
    }
}
