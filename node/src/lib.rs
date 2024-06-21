pub mod blockchain;
pub mod comm;
pub mod utils;
pub mod share {
    use crate::utils::{difficulty_from_u8, gen_address, get_timestamp, sync_coinbase};
    use astro_float::BigFloat;
    use chrono::Utc;
    use clap::Parser;
    use openssl::pkey::PKey;
    use serde_json::json;
    use std::fs;
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

        /// entry from node to join the network
        #[arg(short, long, default_value_t = String::from("127.0.0.1:8000"))]
        node: String,

        /// expected time to mine a block
        /// 2m:3h:5d:2w - valid after 2 minutes, 3 hours, 5 days, 2 weeks
        #[arg(short, long, default_value_t = String::from("10m"))]
        expected: String,

        /// initial difficulty to start with
        #[arg(short, long, default_value_t = 15)]
        difficulty_initial: u8,

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

        /// lock sync request after syncing for x blocks
        #[arg(short, long, default_value_t = 3)]
        checklock: u8,

        /// sync from entry node
        #[arg(short, long, default_value_t = false)]
        sync: bool,
    }

    #[derive(Debug)]
    pub struct Args_ {
        pub ip: String,
        pub port: u16,
        pub genisis: bool,
        pub node: String,
        pub expected: u64,
        pub difficulty_initial: u8,
        pub tx_per_block: u16,
        pub wallet: String,
        pub reward: f64,
        pub halving: u64,
        pub fee: u8,
        pub checklock: u8,
        pub sync: bool,
    }
    impl Args_ {
        /// Return the necessary information for synchronization as json.
        pub fn as_json(&self) -> serde_json::Value {
            json!({
                "expected": self.expected,
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
    pub static DB_HEAD_PATH: OnceLock<String> = OnceLock::new();
    pub static DB_POS_PATH: OnceLock<String> = OnceLock::new();
    pub static DB_TXS_PATH: OnceLock<String> = OnceLock::new();
    pub static mut DIFFICULTY: OnceLock<BigFloat> = OnceLock::new();
    pub static FEE: OnceLock<u8> = OnceLock::new();

    fn parse_args() -> Args_ {
        let mut args = Args::parse();
        if !args.genisis && args.port != 8000 {
            args.sync = true;
        }
        let expected = match get_timestamp(&args.expected) {
            Ok(n) => match (n).try_into() {
                Ok(n) => n,
                Err(e) => {
                    eprintln!(
                        "[#] ARGS - convert exptected time (difficulty) to unsigned error: {}",
                        e
                    );
                    exit(1);
                }
            },
            Err(e) => {
                eprintln!("[#] ARGS - get exptected time (difficulty) error: {}", e);
                exit(1);
            }
        };
        Args_ {
            ip: args.ip,
            port: args.port,
            genisis: args.genisis,
            node: args.node,
            expected,
            difficulty_initial: args.difficulty_initial,
            tx_per_block: args.txpb,
            wallet: args.wallet,
            reward: args.reward,
            halving: args.halving,
            fee: args.fee,
            checklock: args.checklock,
            sync: args.sync,
        }
    }

    pub fn init() {
        unsafe {
            // get args
            ARGS.get_or_init(|| parse_args());
            let args = ARGS.get().unwrap();

            // check args
            if args.difficulty_initial < 1 || args.difficulty_initial > 71 {
                eprintln!("[#] ARGS - invalid difficulty (allowed: 1 - 71)");
                exit(1);
            }
            if args.fee > 100 {
                eprintln!("[#] ARGS - invalid fee (allowed: 0% - 100%)");
                exit(1);
            }
            // format address
            ADDR.get_or_init(|| format!("{}:{}", args.ip, args.port));

            // initialize fee
            FEE.get_or_init(|| args.fee);

            // initialize difficulty
            DIFFICULTY.get_or_init(|| difficulty_from_u8(args.difficulty_initial));

            // set coinbase address
            let args = ARGS.get().unwrap();
            if !args.genisis && args.sync {
                // synchronize address
                match sync_coinbase(&args.node) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("[#] COINBASE - sync error: {}", e);
                        exit(1);
                    }
                }
            } else {
                // generate coinbase address
                let c = Utc::now().timestamp().to_string();
                let priv_key = PKey::generate_ed448().unwrap();
                let pub_key = priv_key.public_key_to_pem().unwrap();
                let address = gen_address(&pub_key, 16, &c);

                // initialize coinbase address
                COINBASE.get_or_init(|| address);
            }
        }
        // create directory
        let path = format!("node/data/{}", unsafe { ARGS.get().unwrap().port });
        match fs::create_dir_all(&path) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("[#] SETUP - create data directory for node error: {}", e);
                exit(1);
            }
        }
        // initialize statics
        DB_HEAD_PATH.get_or_init(|| format!("{}/{}", path, "head"));
        DB_POS_PATH.get_or_init(|| format!("{}/{}", path, "position"));
        DB_TXS_PATH.get_or_init(|| format!("{}/{}", path, "transaction"));
    }
}
