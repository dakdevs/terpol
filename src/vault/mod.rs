pub mod encrypted_file;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("vault is locked or corrupted")]
    Corrupted,
    #[error("wrong password")]
    WrongPassword,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encryption error: {0}")]
    Encryption(String),
}

pub trait VaultBackend: Send + Sync {
    fn get(&self, key: &str) -> Result<String, VaultError>;
    fn set(&mut self, key: &str, value: &str) -> Result<(), VaultError>;
    fn delete(&mut self, key: &str) -> Result<(), VaultError>;
    fn list(&self) -> Result<Vec<String>, VaultError>;
}
