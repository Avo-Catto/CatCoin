#[derive(Debug)]
pub enum PoolError {
    DuplicatedTransaction,
}

#[derive(Debug)]
pub enum BlockChainError {
    BlockAlreadyInChain,
    InvalidBlock
}

#[derive(Debug)]
pub enum TransactionValidationError {
    MismatchSource,
    MismatchDestination,
    MismatchDate,
    MismatchHash,
}

#[derive(Debug)]
pub enum BlockError {
    MismatchDate,
    TransactionValidationFailed,
    MismatchPreviousHash,
    MismatchHash,
    MismatchMerkleHash,
}
