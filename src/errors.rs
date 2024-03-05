#[derive(Debug)]
pub enum PoolError {
    DuplicatedTransaction,
}

#[derive(Debug)]
pub enum BlockChainError {
    DuplicatedBlock,
    InvalidBlock
}
