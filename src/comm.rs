use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
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

#[derive(Debug, Deserialize)]
pub enum AddTransactionResponse {
    ConstructionError,
    DuplicatedTransaction,
    FailedCheck,
    ParsingError,
    Success,
}

#[derive(Debug, Deserialize)]
pub enum CheckBlockchainResponse {
    Success,
}

#[derive(Deserialize, Debug, Serialize)]
pub enum Dtype {
    AddPeer,
    AddTransaction,
    CheckBlockchain,
    GetBlockchain,
    GetDifficulty,
    GetLatestBlock,
    GetPeers,
    GetTransactionPool,
    PostBlock,
}

#[derive(Debug, Deserialize, PartialEq)]
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

#[derive(Debug, Deserialize)]
pub struct Response<T> {
    pub addr: String,
    pub res: T,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct Request<T> {
    pub dtype: Dtype,
    pub data: T,
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
    data: &String,
) -> (Vec<Response<T>>, Vec<String>)
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
{
    let mut peers_failed: Vec<String> = Vec::new();
    let mut responses = Vec::new();

    // craft request
    let req = Request { dtype, data };
    println!("DEBG - broadcast send: {:?}", req); // DEBUG
    for peer in peers {
        // send request
        let stream = match request(peer, &req) {
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
    // receive response
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();

    println!("DEBUG - RECEIVED: {}", buf); // DEBUG

    // get ip address
    let addr = match stream.local_addr() {
        Ok(n) => n.to_string(),
        Err(e) => return Err(Box::new(e)),
    };

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

pub fn request<T>(addr: &String, req: &Request<T>) -> Result<TcpStream, Box<dyn Error>>
where
    T: serde::Serialize,
{
    // connect to node
    let mut stream = match TcpStream::connect(addr) {
        Ok(n) => n,
        Err(e) => return Err(Box::new(e)),
    };
    // send request
    let json = json!({"dtype": req.dtype, "data": req.data});
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
