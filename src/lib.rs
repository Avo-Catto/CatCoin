// modules
pub mod blockchain;
pub mod comm;
pub mod utils;
pub mod args {
    use clap::Parser;
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
    }

    #[derive(Debug)]
    pub struct Args_ {
        pub ip: String,
        pub port: u16,
        pub genisis: bool,
        pub entry: String,
        pub difficulty: u8,
    }

    pub static ARGS: OnceLock<Args_> = OnceLock::new();
    pub static ADDR: OnceLock<String> = OnceLock::new();

    pub fn parse_args() -> Args_ {
        let args = Args::parse();
        Args_ {
            ip: args.ip,
            port: args.port,
            genisis: args.genisis,
            entry: args.entry,
            difficulty: args.difficulty,
        }
    }

    pub fn init() {
        // get args
        ARGS.get_or_init(|| parse_args());

        // format address
        ADDR.get_or_init(|| format!("{}:{}", ARGS.get().unwrap().ip, ARGS.get().unwrap().port));
        // check args
        if ARGS.get().unwrap().difficulty < 1 || ARGS.get().unwrap().difficulty > 71 {
            eprintln!("[#] ARGS - invalid difficulty (allowed: 1 - 71)");
            exit(1);
        }
    }
}
