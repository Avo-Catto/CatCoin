use crate::args::ADDR;
use rand::{seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    error::Error,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
};

#[derive(Deserialize)]
pub enum AddPeerResponse {
    AlreadyExist,
    FailedCheck,
    Success,
}
impl std::fmt::Debug for AddPeerResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddPeerResponse::AlreadyExist => write!(f, "\"AlreadyExist\""),
            AddPeerResponse::FailedCheck => write!(f, "\"FailedCheck\""),
            AddPeerResponse::Success => write!(f, "\"Success\""),
        }
    }
}

#[derive(Deserialize, PartialEq)]
pub enum AddTransactionResponse {
    ConstructionError,
    DuplicatedTransaction,
    FailedCheck,
    ParsingError,
    Success,
}
impl std::fmt::Debug for AddTransactionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddTransactionResponse::ConstructionError => write!(f, "\"ConstructionError\""),
            AddTransactionResponse::DuplicatedTransaction => write!(f, "\"DuplicatedTransaction\""),
            AddTransactionResponse::FailedCheck => write!(f, "\"FailedCheck\""),
            AddTransactionResponse::ParsingError => write!(f, "\"ParsingError\""),
            AddTransactionResponse::Success => write!(f, "\"Success\""),
        }
    }
}

#[derive(Deserialize)]
pub enum CheckSyncResponse {
    OK,
}
impl std::fmt::Debug for CheckSyncResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckSyncResponse::OK => write!(f, "\"OK\""),
        }
    }
}

#[derive(Deserialize, PartialEq)]
pub enum PostBlockResponse {
    AddToChainError,
    ConstructionError,
    MismatchCurrentlyMinedBlock,
    MismatchHashDifficulty,
    ParsingHashValError,
    ParsingJsonError,
    Success,
    ValidationError,
}
impl std::fmt::Debug for PostBlockResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostBlockResponse::AddToChainError => write!(f, "\"AddToChainError\""),
            PostBlockResponse::ConstructionError => write!(f, "\"ConstructionError\""),
            PostBlockResponse::MismatchCurrentlyMinedBlock => {
                write!(f, "\"MismatchCurrentlyMinedBlock\"")
            }
            PostBlockResponse::MismatchHashDifficulty => write!(f, "\"MismatchHashDifficulty\""),
            PostBlockResponse::ParsingHashValError => write!(f, "\"ParsingHashValError\""),
            PostBlockResponse::ParsingJsonError => write!(f, "\"ParsingJsonError\""),
            PostBlockResponse::Success => write!(f, "\"Success\""),
            PostBlockResponse::ValidationError => write!(f, "\"ValidationError\""),
        }
    }
}

#[derive(Deserialize)]
pub struct GetBlockReceiver {
    pub block: serde_json::Value,
    pub len: u64,
}

#[derive(Deserialize, Debug, Serialize)]
pub enum Dtype {
    AddPeer,
    AddTransaction,
    CheckSync,
    GetBlock,
    GetBlockchain,
    GetDifficulty,
    GetPeers,
    GetPoolHash,
    // GetTransactionsPerBlock,
    GetTransactionPool,
    PostBlock,
    Skip,
}

#[derive(Debug, Deserialize)]
pub struct Response<T> {
    pub addr: String,
    pub res: T,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct Request<T> {
    pub dtype: Dtype,
    pub data: T,
    pub addr: String,
}

#[derive(Deserialize)]
struct _ResponseReceiver<T> {
    pub res: T,
}

/// Sends a String to a list of peers, returns a list of arrays of response and address, and unreachable peers.
/// Example return: `(Vec<responses>, Vec<addresses_failed>)`
pub fn broadcast<T>(
    peers: &Vec<String>,
    dtype: Dtype,
    data: &str,
) -> (Vec<Response<T>>, Vec<String>)
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
{
    let mut peers_failed: Vec<String> = Vec::new();
    let mut responses = Vec::new();
    let mut peers = peers.clone();
    peers.shuffle(&mut thread_rng());

    // craft request
    let req = Request {
        dtype,
        data,
        addr: ADDR.get().unwrap().to_string(),
    };
    // send request
    for peer in peers {
        let stream = match request(&peer, &req) {
            Ok(n) => n,
            Err(_) => {
                peers_failed.push(peer.clone());
                continue;
            }
        };
        // receive response
        match receive(stream) {
            Ok(n) => {
                println!("DEBUG - broadcast received: {:?}", n); // DEBUG
                responses.push(n);
            }
            Err(e) => {
                eprintln!("DEBUG - broadcast receive error: {}", e); // DEBUG
                continue;
            }
        };
    }
    println!("DEBUG - broadcast responses: {:?}", responses); // DEBUG
    (responses, peers_failed)
}

pub fn receive<T>(mut stream: TcpStream) -> Result<Response<T>, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    // get ip address
    let addr = match stream.peer_addr() {
        Ok(n) => n.to_string(),
        Err(e) => return Err(Box::new(e)),
    };
    // receive response
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();

    // parse response
    match serde_json::from_str::<_ResponseReceiver<T>>(&buf) {
        Ok(n) => Ok(Response { addr, res: n.res }),
        Err(e) => Err(Box::new(e)),
    }
}

pub fn respond<T>(mut stream: &TcpStream, res: T)
where
    T: std::fmt::Debug,
{
    match stream.write_all(format!("{{\"res\": {:?}}}", res).as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[#] respond[{:?}] - write stream error: {:?}", stream, e);
            return;
        }
    }
    match stream.shutdown(Shutdown::Write) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[#] respond[{:?}] - shutdown stream error: {:?}", stream, e);
        }
    }
}

pub fn request<T>(addr: &str, req: &Request<T>) -> Result<TcpStream, Box<dyn Error>>
where
    T: serde::Serialize,
{
    // connect to node
    let mut stream = match TcpStream::connect(addr) {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    };
    // send request
    let json = json!({"dtype": req.dtype, "data": req.data, "addr": req.addr});
    match stream.write_all(json.to_string().as_bytes()) {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    }
    match stream.shutdown(Shutdown::Write) {
        Ok(_) => (),
        Err(e) => return Err(Box::new(e)),
    }
    Ok(stream)
}
