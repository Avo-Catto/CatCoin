#[derive(Debug)]
pub enum PoolError {
    DuplicatedTransaction,
}

pub enum BlockChainError {
    DuplicatedBlock,
    InvalidBlock
}
