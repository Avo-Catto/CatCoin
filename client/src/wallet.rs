extern crate aes_gcm;
extern crate bs58;
extern crate chrono;
extern crate md5;
extern crate node;
extern crate openssl;
extern crate rand;
extern crate rcgen;
extern crate serde;
extern crate serde_json;
extern crate sha2;
use self::aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use self::chrono::Utc;
use self::node::{
    comm::{receive, request, Dtype, Request},
    utils::TVE,
};
use self::openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    sign::{Signer, Verifier},
    symm::Cipher,
};
use self::rand::{thread_rng, Rng};
use self::serde::{Deserialize, Serialize};
use self::serde_json::json;
use self::sha2::{Digest, Sha224, Sha256, Sha512};
use crate::{output, ADDRESS, FEE, KEY_PATH, WALLET_PATH};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    str::FromStr,
};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub src: String,        // Address of sender
    pub dst: String,        // Address of receiver
    pub val: f64,           // Amount of coins
    pub timestamp: i64,     // when transaction will be valid
    pub signature: Vec<u8>, // signature
    pub pub_key: Vec<u8>,   // public key
    pub broadcast: bool,    // should the transaction be broadcasted - always true
    pub fee: f64,           // Address of node to receive it's fees
}

impl Transaction {
    // Constructor
    pub fn new(src: &str, dst: &str, val: f64, after: &str) -> Result<Self, Box<dyn Error>> {
        let add = match get_timestamp(after) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        Ok(Transaction {
            src: src.to_string(),
            dst: dst.to_string(),
            val,
            timestamp: timestamp_now() + add,
            signature: Vec::new(),
            pub_key: Vec::new(),
            broadcast: true,
            fee: calc_fee(val),
        })
    }

    pub fn as_json(&self) -> serde_json::Value {
        json!({
            "src": self.src,
            "dst": self.dst,
            "val": self.val,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "pub_key": self.pub_key,
            "broadcast": self.broadcast,
            "fee": self.fee,
        })
    }

    /// Check signature.
    fn check_sign(&self) -> Result<bool, ErrorStack> {
        // load public key
        let pkey = match PKey::public_key_from_pem(&self.pub_key) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        // construct verifier
        let mut verifier = match Verifier::new(MessageDigest::sha1(), &pkey) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        println!("\nDEBUG - check signature:\n{:?}\n", self); // DEBUG

        // feed the verifier with delicious data
        match verifier.update(self.signature_fmt().as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] TRANSACTION:verify - update verifier error: {}", e);
                return Err(e);
            }
        };
        // verify
        verifier.verify(&self.signature)
    }

    /// Construct a transaction from json.
    pub fn from_json(
        json: &serde_json::Value,
    ) -> Result<Transaction, Box<dyn std::any::Any + Send>> {
        std::panic::catch_unwind(|| {
            // initial data
            Transaction {
                src: json
                    .get("src")
                    .expect("Transaction::from_json: src")
                    .to_string()
                    .replace('"', ""),
                dst: json
                    .get("dst")
                    .expect("Transaction::from_json: dst")
                    .to_string()
                    .replace('"', ""),
                val: json
                    .get("val")
                    .expect("Transaction::from_json: val")
                    .as_f64()
                    .expect("Transaction::from_json: val as f64"),
                timestamp: json
                    .get("timestamp")
                    .expect("Transaction::from_json: timestamp")
                    .as_i64()
                    .expect("Transaction::from_json: timestamp as i64"),
                signature: json
                    .get("signature")
                    .expect("Transaction::from_json: signature")
                    .as_array()
                    .expect("Transaction::from_json: signature as array")
                    .iter()
                    .map(|x| {
                        x.as_u64()
                            .expect("Transaction::from_json: signature value as u64")
                            as u8
                    })
                    .collect(),
                pub_key: json
                    .get("pub_key")
                    .expect("Transaction::from_json: public key")
                    .as_array()
                    .expect("Transaction::from_json: public key as array")
                    .iter()
                    .map(|x| {
                        x.as_u64()
                            .expect("Transaction::from_json: public key value as u64")
                            as u8
                    })
                    .collect(),
                broadcast: json
                    .get("broadcast")
                    .expect("Transaction::from_json: broadcast")
                    .as_bool()
                    .expect("Transaction::from_json: broadcast as bool"),
                fee: json
                    .get("fee")
                    .expect("Trnasaction::from_json: fee")
                    .as_f64()
                    .expect("Transaction::from_json: fee as f64"),
            }
        })
    }

    /// Sign the transaction.
    pub fn sign(&mut self, wallet: &Wallet) -> Result<(), Box<dyn Error>> {
        self.pub_key = wallet.pub_key.clone();
        let priv_key = match PKey::private_key_from_pem_passphrase(
            &wallet.priv_key,
            wallet.passphrase.as_bytes(),
        ) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] TRANSACTION:sign - load private key error: {}", e);
                return Err(Box::new(e));
            }
        };
        let mut signer = match Signer::new(MessageDigest::sha1(), &priv_key) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] TRANSACTION:sign - construct signer error: {}", e);
                return Err(Box::new(e));
            }
        };

        println!("\nDEBUG - what's going to be signed:\n{:?}\n", self); // DEBUG

        match signer.update(self.signature_fmt().as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] TRANSACTION:sign - update signer error: {}", e);
                return Err(Box::new(e));
            }
        };
        self.signature = match signer.sign_to_vec() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] TRANSACTION:sign - sign transaction error: {}", e);
                return Err(Box::new(e));
            }
        };
        Ok(())
    }

    /// Signature format for signing and checking signature.
    fn signature_fmt(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}-{:#?}",
            self.src, self.dst, self.timestamp, self.fee, self.val, self.pub_key
        )
    }

    /// Check entire transaction.
    pub fn validate(&self) -> Result<(), TVE> {
        // check source
        if !check_addr_by_key(&self.src, &self.pub_key) {
            return Err(TVE::InvalidSource);
        }
        if !check_addr_by_sum(&self.src) {
            return Err(TVE::InvalidSource);
        }
        // check destination
        if !check_addr_by_sum(&self.dst) {
            return Err(TVE::InvalidDestination);
        }
        // check value
        if self.val < 0.0 {
            return Err(TVE::InvalidValue);
        }
        // check balance
        let balance = match get_balance(&self.src) {
            Ok(n) => n,
            Err(_) => return Err(TVE::BalanceError),
        };
        if balance < self.val + self.fee {
            return Err(TVE::InvalidBalance);
        }
        // check signature
        match self.check_sign() {
            Ok(n) => {
                if !n {
                    return Err(TVE::InvalidSignature);
                }
            }
            Err(e) => {
                eprintln!("[#] TRANSACTION:validate - check signature error: {}", e);
                return Err(TVE::SignatureError);
            }
        }
        Ok(())
    }
}
impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "  Source: {}\n  Destination: {}\n  Timestamp: {}\n  Value: {}\n  Fee: {}\n",
            self.src, self.dst, self.timestamp, self.val, self.fee
        )
    }
}

#[derive(Debug)]
pub struct Wallet {
    pub addr_salts: Vec<String>,
    pub idx_addr: u32,
    pub placeholder: bool,
    pub pub_key: Vec<u8>,
    passphrase: String,
    priv_key: Vec<u8>,
    salt: String,
    uid: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct WalletReader {
    pub addr_salts: Vec<String>,
    pub idx_addr: u32,
    pub passphrase: String,
    pub salt: String,
}

impl Wallet {
    // Constructor
    pub fn new(mnemonics: Vec<String>, uid: Uuid, password: &str) -> Result<Self, Box<dyn Error>> {
        // generate keypair
        let rsa = Rsa::generate(4096).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let cipher = Cipher::camellia_256_cbc();

        // passphrase
        let salt = gen_salt(12);
        let passphrase = Self::get_passphrase(&mnemonics, &salt);

        // grep keys and do fancy stuff with it
        let pub_key = pkey.public_key_to_pem().unwrap();
        let priv_key = pkey
            .private_key_to_pem_pkcs8_passphrase(cipher, &passphrase.as_bytes())
            .unwrap();

        // construct
        let wallet = Wallet {
            addr_salts: Vec::new(),
            idx_addr: 0,
            placeholder: false,
            pub_key,
            passphrase,
            priv_key,
            salt,
            uid,
        };
        // store keys
        let _ = wallet.save(password);
        Ok(wallet)
    }

    /// Get wallet by uuid and password.
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
        // construct wallet
        Ok(Wallet {
            idx_addr: json.idx_addr,
            placeholder: false,
            addr_salts: json.addr_salts,
            passphrase: json.passphrase,
            priv_key,
            pub_key,
            salt: json.salt,
            uid,
        })
    }

    fn get_passphrase(mnemonics: &Vec<String>, salt: &String) -> String {
        let passphrase = format!("{}${}", mnemonics.concat(), salt);
        format!("{:x}", Sha256::digest(passphrase.as_bytes()))
    }

    /// Construct a new wallet without any initializations unlike Self::new().
    pub fn placeholder() -> Self {
        Wallet {
            idx_addr: 0,
            placeholder: true,
            addr_salts: Vec::new(),
            passphrase: String::new(),
            priv_key: Vec::new(),
            pub_key: Vec::new(),
            salt: String::new(),
            uid: Uuid::new_v4(),
        }
    }

    /// Save the keys and the wallet data.
    pub fn save(&self, password: &str) -> Result<(), Box<dyn Error>> {
        // wallet
        let wallet = json!({
            "addr_salts": self.addr_salts,
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
}

/// Convert address to pattern.
pub fn addr_to_pattern(addr: &str) -> Vec<u8> {
    let out: Vec<u8> = addr.bytes().map(|x| x % 2).collect();
    out
}

/// Calculate the fee of a transaction by it's value.
pub fn calc_fee(val: f64) -> f64 {
    let fee = *unsafe { FEE.get().unwrap() };
    let fee = fee as f64;
    val * (fee / 100.0)
}

/// Validate an address.
pub fn check_addr_by_key(addr: &str, pub_key: &Vec<u8>) -> bool {
    // check length
    if !check_addr_len(addr) {
        return false;
    }
    // decode address
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(n) => n,
        Err(e) => {
            output(&format!(
                "Transaction::check_address - validate address error: {}",
                e,
            ));
            return false;
        }
    };
    // extract salt & index
    let salt = String::from_utf8_lossy(&decoded[21..33]).to_string();
    let idx: u32 = match String::from_utf8_lossy(&decoded[33..]).parse() {
        Ok(n) => n,
        Err(e) => {
            eprintln!(" [#]  parse index error: {}", e);
            return false;
        }
    };
    // validate address
    if gen_address(pub_key, idx, &salt) != addr {
        eprintln!(
            "not equal: {:?} - idx:{:?} - salt:{:?} - key:{:?}",
            gen_address(pub_key, idx, &salt),
            idx,
            salt,
            pub_key
        );
        return false;
    }
    true
}

/// Check address by checksum.
pub fn check_addr_by_sum(addr: &str) -> bool {
    // check length
    if !check_addr_len(addr) {
        println!("address too short: {}", addr.len()); // DEBUG
        return false;
    }
    // decode address
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("validate address error: {}", e);
            return false;
        }
    };
    // compare checksums
    Sha224::digest(&decoded[5..])[..5] == decoded[..5]
}

/// Check length of address.
pub fn check_addr_len(addr: &str) -> bool {
    addr.as_bytes().len() > 43
}

/// Check if a user already has a wallet.
pub fn check_wallet_exists(uid: Uuid) -> bool {
    match fs::File::open(format!("{}/{}", WALLET_PATH, uid)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Decrypt data using a password.
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

/// Encrypt data using a password.
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

/// Generate an address.
/// Structure: `{checksum 4}:{hash 32}:{salt 4}:{index}`
pub fn gen_address(pub_key: &Vec<u8>, idx: u32, salt: &String) -> String {
    // hash public key
    let mut a = Sha512::digest(pub_key).to_vec();
    let mut b = a.clone();

    // append salt & index for uniqueness
    b.extend_from_slice(format!("{}{}", salt, idx).as_bytes());
    a.extend_from_slice(&Sha512::digest(&b));

    // hash again
    let mut c = md5::compute(Sha256::digest(&a[32..96])).to_vec();
    c.extend_from_slice(format!("{}{}", salt, idx).as_bytes());

    // checksum
    let checksum = &Sha224::digest(&c)[..5];
    let mut result = checksum.to_vec();
    result.extend_from_slice(&c);

    // encode address
    let f = bs58::encode(result).into_string();
    f
}

/// Generate a salt.
pub fn gen_salt(len: usize) -> String {
    let mut out: Vec<String> = Vec::new();
    for _ in 0..len {
        let i: u16 = Rng::gen(&mut thread_rng());
        let c = match char::from_u32(i as u32) {
            Some(n) => n,
            None => continue,
        };
        out.push(c.to_string());
    }
    out.concat()
}

// TODO: balance and future balance
pub fn get_balance(addr: &str) -> Result<f64, Box<dyn Error>> {
    let transactions = match get_transactions(addr) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    let mut value = 0_f64;
    for tx in transactions {
        if tx.src == addr.to_string() {
            value -= tx.val + tx.fee;
        } else if &tx.dst == addr {
            value += tx.val;
        }
    }
    Ok(value)
}

/// Get the timestamp by human notation.
/// Example:
/// 2m:3h:5d:2w - valid after 2 minutes, 3 hours, 5 days, 2 weeks
pub fn get_timestamp(syntax: &str) -> Result<i64, Box<dyn Error>> {
    let syntax = syntax.to_string();
    if syntax.len() < 3 {
        return Ok(0);
    }
    let mut out = 0_i64;
    for i in syntax.split(':') {
        let (multi, t) = i.split_at(i.len() - 1);
        let multi: i64 = match multi.parse() {
            Ok(n) => n,
            Err(e) => return Err(Box::new(e)),
        };
        match t {
            "m" => out += 60 * multi,
            "h" => out += 60 * 60 * multi,
            "d" => out += 60 * 60 * 24 * multi,
            "w" => out += 60 * 60 * 24 * 7 * multi,
            _ => (),
        }
    }
    Ok(out)
}

pub fn get_transactions(addr: &str) -> Result<Vec<Transaction>, Box<dyn Error>> {
    // craft request
    let req = Request {
        dtype: Dtype::GetTransactions,
        data: json!(addr_to_pattern(addr)).to_string(),
        addr: String::new(),
    };
    // send request
    let stream = match request(unsafe { ADDRESS.get().unwrap() }, &req) {
        Ok(n) => n,
        Err(e) => {
            output(&format!("get_transactions - request error: {}", e));
            return Err(e);
        }
    };
    // receive transactions
    let res = match receive::<Vec<String>>(stream) {
        Ok(n) => n,
        Err(e) => {
            output(&format!("get_transactions - receive error: {}", e));
            return Err(e);
        }
    };
    // parse transactions
    let mut tmp: Vec<Transaction> = Vec::new();
    for i in res.res {
        // parse to json
        let i: serde_json::Value = match serde_json::Value::from_str(&i) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTIONPOOL:SYNC - parse transaction to json error: {}",
                    e
                );
                return Err(Box::new(e));
            }
        };
        // construct Transaction
        let transaction = match Transaction::from_json(&i) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "[#] TRANSACTIONPOOL:SYNC - transaction construction error: {:?}",
                    e
                );
                return Err(format!("transaction construction error: {:?}", e).into());
            }
        };
        tmp.push(transaction);
    }
    // filter transactions
    let mut transactions: Vec<Transaction> = Vec::new();
    for tx in tmp {
        if addr == &tx.src || addr == &tx.dst {
            transactions.push(tx)
        }
    }
    Ok(transactions)
}

/// Request fee percentage from node and `None` if the value was invalid.
pub fn request_fee() -> Result<Option<u8>, Box<dyn Error>> {
    // craft request
    let req = Request {
        dtype: Dtype::GetFee,
        data: "",
        addr: String::new(),
    };
    // send request
    let stream = match request(unsafe { ADDRESS.get().unwrap() }, &req) {
        Ok(n) => n,
        Err(e) => {
            output(&format!("request_fee - request error: {}", e));
            return Err(e);
        }
    };
    // receive response
    let res = match receive::<u8>(stream) {
        Ok(n) => n,
        Err(e) => {
            output(&format!("request_fee - receive error: {}", e));
            return Err(e);
        }
    };
    // check fee
    if res.res > 100 {
        Ok(None)
    } else {
        Ok(Some(res.res))
    }
}

/// Returns the current timestamp.
pub fn timestamp_now() -> i64 {
    Utc::now().timestamp()
}

pub fn test() {
    for i in 0..4 {
        println!("{}", i);
    }

    // craft request
    let req = Request {
        dtype: Dtype::GetBlock,
        data: "3",
        addr: String::new(),
    };
    // send request
    let stream = match request(unsafe { ADDRESS.get().unwrap() }, &req) {
        Ok(n) => n,
        Err(e) => {
            output(&format!("TEST - request error: {}", e));
            return;
        }
    };
    // receive response
    let res = match receive::<String>(stream) {
        Ok(n) => n,
        Err(e) => {
            output(&format!("TEST - receive error: {}", e));
            return;
        }
    };
    print!("DEBUG - OUTPUT:\n{:#?}\n", res);
}
