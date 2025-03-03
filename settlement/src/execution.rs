use super::*;
use simperby_common::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Execution {
    /// The target settlement chain which this message will be delivered to.
    pub target_chain: String,
    /// A unique sequence for the target contract.
    pub contract_sequence: u128,
    /// The actual content to deliver.
    pub message: ExecutionMessage,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum ExecutionMessage {
    /// Does nothing but make the treasury contract verify the commitment anyway.
    Dummy { msg: String },
    /// Transfers a fungible token from the treasury contract.
    TransferFungibleToken(TransferFungibleToken),
    /// Transfers an NFT from the treasury contract.
    TransferNonFungibleToken(TransferNonFungibleToken),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct TransferFungibleToken {
    pub token_address: String,
    pub amount: u128,
    pub receiver_address: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct TransferNonFungibleToken {
    pub collection_address: String,
    pub token_index: String,
    pub receiver_address: String,
}

/// Creates an execution transaction that will be delivered to the target chain once finalized.
pub fn create_execution_transaction(
    execution: &Execution,
    author: PublicKey,
    timestamp: Timestamp,
) -> Result<Transaction, String> {
    let head = match &execution.message {
        ExecutionMessage::Dummy { .. } => format!("ex-dummy: {}", execution.target_chain),
        ExecutionMessage::TransferFungibleToken(_) => {
            format!("ex-transfer-ft: {}", execution.target_chain)
        }
        ExecutionMessage::TransferNonFungibleToken(_) => {
            format!("ex-transfer-nft: {}", execution.target_chain)
        }
    };
    let body = serde_spb::to_string(&execution).unwrap();
    Ok(Transaction {
        author,
        timestamp,
        head,
        body,
        diff: Diff::None,
    })
}

/// Reads an execution transaction and tries to extract an execution message.
pub fn convert_transaction_to_execution(transaction: &Transaction) -> Result<Execution, String> {
    let execution: Execution = serde_spb::from_str(&transaction.body).map_err(|e| e.to_string())?;
    if !transaction.head.starts_with("ex-") {
        return Err("Invalid head".to_string());
    }
    let execution_message =
        transaction.head.split(": ").next().ok_or("Invalid head")?[3..].to_owned();
    let target_chain = transaction.head.split(": ").nth(1).ok_or("Invalid head")?;
    if execution.target_chain != target_chain {
        return Err("Invalid target chain".to_string());
    }
    match execution_message.as_str() {
        "dummy" => {
            if !matches!(execution.message, ExecutionMessage::Dummy { .. }) {
                return Err("Invalid message".to_string());
            }
        }
        "transfer-ft" => {
            if !matches!(
                execution.message,
                ExecutionMessage::TransferFungibleToken { .. }
            ) {
                return Err("Invalid message".to_string());
            }
        }
        "transfer-nft" => {
            if !matches!(
                execution.message,
                ExecutionMessage::TransferNonFungibleToken { .. }
            ) {
                return Err("Invalid message".to_string());
            }
        }
        _ => return Err("Invalid message".to_string()),
    }
    Ok(execution)
}
