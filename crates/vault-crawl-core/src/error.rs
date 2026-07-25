use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrawlError {
    #[error("{outcome}: {message}; terminal receipt: {receipt_path}")]
    Terminal {
        outcome: String,
        message: String,
        receipt_path: String,
    },
    #[error("policy refused request: {0}")]
    Refused(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("network failure: {0}")]
    Network(String),
    #[error("parser failure: {0}")]
    Parser(String),
    #[error("storage failure: {0}")]
    Storage(String),
    #[error("database failure: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization failure: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

impl CrawlError {
    #[must_use]
    pub fn terminal_outcome(&self) -> Option<&str> {
        match self {
            Self::Terminal { outcome, .. } => Some(outcome),
            _ => None,
        }
    }

    #[must_use]
    pub fn terminal_receipt_path(&self) -> Option<&str> {
        match self {
            Self::Terminal { receipt_path, .. } => Some(receipt_path),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, CrawlError>;
