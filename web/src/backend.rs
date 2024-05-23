extern crate bs58;
extern crate openssl;
extern crate rand;
extern crate rcgen;
extern crate sha2;

// use self::bs58;
use self::openssl::{pkey::PKey, rsa::Rsa, symm::Cipher};
use self::rand::{thread_rng, Rng};
use self::sha2::{Digest, Sha256, Sha512};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

pub struct Wallet {
    passphrase: String,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    salt: String,
    idx_addr: u32,
    uid: String,
}

// TODO: alphabetic order & docs
impl Wallet {
    // Constructor
    pub fn new(mnemonics: Vec<String>, uid: &str) -> Result<Self, Box<dyn Error>> {
        // generate keypair
        let rsa = Rsa::generate(4096).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let cipher = Cipher::camellia_256_cbc();

        // passphrase
        let salt = Self::gen_salt();
        let passphrase = Self::get_passphrase(&mnemonics, &salt);
        println!("passhprase: {}", passphrase);

        // grep keys and do fancy stuff with it
        let pub_key = pkey.public_key_to_pem().unwrap();
        let priv_key = pkey
            .private_key_to_pem_pkcs8_passphrase(cipher, &passphrase.as_bytes())
            .unwrap();

        // DEBUG
        let priv_key_str = String::from_utf8(priv_key.clone()).unwrap();
        let pub_key_str = String::from_utf8(pub_key.clone()).unwrap();
        println!("\n{}", priv_key_str);
        println!("\n{}", pub_key_str);

        // construct
        let wallet = Wallet {
            passphrase,
            pub_key,
            priv_key,
            salt,
            idx_addr: 0,
            uid: uid.to_string(),
        };
        wallet.save_keys();
        Ok(wallet)
    }

    pub fn from(uid: &str) {
        // -> Result<Self, std::io::Error> {
        // TODO: -> Result<Self, ()> {
        let (pub_key, priv_key) = match Self::load_keys(uid) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:from - load keys error: {}", e);
                (String::new(), String::new()) // return Err(e);
            }
        };

        // Ok(Wallet)

        // TODO: get the rest of the data from a database
        // TODO: construct wallet here:

        /*
        Wallet {
        }
        */
    }

    fn get_passphrase(mnemonics: &Vec<String>, salt: &String) -> String {
        let passphrase = format!("{}${}", mnemonics.concat(), salt);
        format!("{:x}${}", Sha256::digest(passphrase.as_bytes()), salt)
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

    fn load_keys(uid: &str) -> Result<(String, String), std::io::Error> {
        // public key
        // open file
        let mut fs = match File::open(format!("web/data/pub_key_{}.pem", uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save_keys - open public key file: {}", e);
                return Err(e);
            }
        };
        // read key from file
        let mut pub_key = String::new();
        fs.read_to_string(&mut pub_key);

        // private key
        // open file
        let mut fs = match File::open(format!("web/data/priv_key_{}.pem", uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save_keys - create private key file: {}", e);
                return Err(e);
            }
        };
        // read key from file
        let mut priv_key = String::new();
        let _ = fs.read_to_string(&mut priv_key);
        Ok((pub_key, priv_key))
    }

    pub fn save_keys(&self) -> Result<(), std::io::Error> {
        // public key
        // create file
        let mut fs = match File::create_new(format!("web/data/pub_key_{}.pem", self.uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save_keys - create public key file: {}", e);
                return Err(e);
            }
        };
        // write key to file
        match fs.write_all(&self.pub_key) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] WALLET:save_keys - write public key error: {}", e);
                return Err(e);
            }
        }
        // private key
        // create file
        let mut fs = match File::create_new(format!("web/data/priv_key_{}.pem", self.uid)) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[#] WALLET:save_keys - create private key file: {}", e);
                return Err(e);
            }
        };
        // write key to file
        match fs.write_all(&self.priv_key) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] WALLET:save_keys - write private key error: {}", e);
                return Err(e);
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

        // append index
        let b = Sha512::digest(a);
        let mut b = b.to_vec();
        b.append(&mut idx.to_be_bytes().to_vec());

        // do some fancy stuff for protection
        let c = Sha512::digest(b);
        let mut c = Sha256::digest(c);
        c = Sha256::digest(&c[0..23]);
        c = Sha256::digest(c);

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
            self.idx_addr += 1;
        }
        f
    }
}
