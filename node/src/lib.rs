pub mod blockchain;
pub mod comm;
pub mod utils;
pub mod share {
    use chrono::Utc;
    use clap::Parser;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::process::exit;
    use std::sync::OnceLock;

    #[derive(Parser, Debug)]
    struct Args {
        /// address of node
        #[arg(short, long, default_value_t = String::from("127.0.0.1"))]
        ip: String,

        /// port of node
        #[arg(short, long, default_value_t = 8000)]
        port: u16,

        /// create genisis block
        #[arg(short, long, default_value_t = false)]
        genisis: bool,

        /// entry node to join the network
        #[arg(short, long, default_value_t = String::from("127.0.0.1:8000"))]
        entry: String,

        /// hash difficulty
        #[arg(short, long, default_value_t = 14)]
        difficulty: u8,

        /// max amount of transactions per block
        #[arg(short, long, default_value_t = 20)]
        txpb: u16,

        /// address of wallet to mine for
        #[arg(short, long, default_value_t = String::new())]
        wallet: String,

        /// starting block reward
        #[arg(short, long, default_value_t = 100.0)]
        reward: f64,

        /// blocks until halving
        #[arg(long, default_value_t = 100)]
        halving: u64,

        /// percentage of fee
        #[arg(short, long, default_value_t = 5)]
        fee: u8,
    }

    #[derive(Debug)]
    pub struct Args_ {
        pub ip: String,
        pub port: u16,
        pub genisis: bool,
        pub entry: String,
        pub difficulty: u8,
        pub tx_per_block: u16,
        pub wallet: String,
        pub reward: f64,
        pub halving: u64,
        pub fee: u8,
    }
    impl Args_ {
        /// Return the necessary information for synchronization as json.
        pub fn as_json(&self) -> serde_json::Value {
            json!({
                "difficulty": self.difficulty,
                "tx_per_block": self.tx_per_block,
                "reward": self.reward,
                "halving": self.halving,
                "fee": self.fee,
            })
        }
    }

    pub static mut ARGS: OnceLock<Args_> = OnceLock::new();
    pub static ADDR: OnceLock<String> = OnceLock::new();
    pub static COINBASE: OnceLock<String> = OnceLock::new();
    pub static FEE: OnceLock<u8> = OnceLock::new();

    fn parse_args() -> Args_ {
        let args = Args::parse();
        Args_ {
            ip: args.ip,
            port: args.port,
            genisis: args.genisis,
            entry: args.entry,
            difficulty: args.difficulty,
            tx_per_block: args.txpb,
            wallet: args.wallet,
            reward: args.reward,
            halving: args.halving,
            fee: args.fee,
        }
    }

    pub fn init() {
        unsafe {
            // get args
            ARGS.get_or_init(|| parse_args());
            let args = ARGS.get().unwrap();

            // check args
            if args.difficulty < 1 || args.difficulty > 71 {
                eprintln!("[#] ARGS - invalid difficulty (allowed: 1 - 71)");
                exit(1);
            }
            if args.fee > 100 {
                eprintln!("[#] ARGS - invalid fee (allowed: 0% - 100%)");
                exit(1);
            }
            // TODO: check if wallet address is valid
            // format address
            ADDR.get_or_init(|| format!("{}:{}", args.ip, args.port));

            // set fee
            FEE.get_or_init(|| args.fee);
        }

        // set coinbase address
        let c = Sha256::digest(Utc::now().timestamp().to_le_bytes());

        // calculate checksum
        let d = Sha256::digest(c);
        let mut checksum = d[0..8].to_vec();

        // append checksum
        let mut c = c.to_vec();
        c.append(&mut checksum);

        // encoded & set address
        COINBASE.get_or_init(|| bs58::encode(&c).into_string());
    }
}
