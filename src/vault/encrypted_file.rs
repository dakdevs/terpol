use super::{VaultBackend, VaultError};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct EncryptedFileVault {
    path: PathBuf,
    secrets: HashMap<String, String>,
    derived_key: [u8; 32],
}

impl EncryptedFileVault {
    pub fn open(path: &Path, password: &str) -> Result<Self, VaultError> {
        if !path.exists() {
            return Self::create_new(path, password);
        }

        let data = std::fs::read(path)?;
        let vault_file: VaultFile =
            serde_json::from_slice(&data).map_err(|_| VaultError::Corrupted)?;

        let derived_key = derive_key(password, &vault_file.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&vault_file.nonce);

        let plaintext = cipher
            .decrypt(nonce, vault_file.ciphertext.as_ref())
            .map_err(|_| VaultError::WrongPassword)?;

        let secrets: HashMap<String, String> =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupted)?;

        Ok(Self {
            path: path.to_path_buf(),
            secrets,
            derived_key,
        })
    }

    fn create_new(path: &Path, password: &str) -> Result<Self, VaultError> {
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let derived_key = derive_key(password, &salt)?;

        let vault = Self {
            path: path.to_path_buf(),
            secrets: HashMap::new(),
            derived_key,
        };
        vault.persist(&salt)?;
        Ok(vault)
    }

    fn persist(&self, salt: &[u8]) -> Result<(), VaultError> {
        let plaintext =
            serde_json::to_vec(&self.secrets).map_err(|e| VaultError::Encryption(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&self.derived_key)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        let vault_file = VaultFile {
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let data =
            serde_json::to_vec(&vault_file).map_err(|e| VaultError::Encryption(e.to_string()))?;
        std::fs::write(&self.path, data)?;
        Ok(())
    }

    fn current_salt(&self) -> Result<Vec<u8>, VaultError> {
        let data = std::fs::read(&self.path)?;
        let vault_file: VaultFile =
            serde_json::from_slice(&data).map_err(|_| VaultError::Corrupted)?;
        Ok(vault_file.salt)
    }
}

impl VaultBackend for EncryptedFileVault {
    fn get(&self, key: &str) -> Result<String, VaultError> {
        self.secrets
            .get(key)
            .cloned()
            .ok_or_else(|| VaultError::KeyNotFound(key.to_string()))
    }

    fn set(&mut self, key: &str, value: &str) -> Result<(), VaultError> {
        self.secrets.insert(key.to_string(), value.to_string());
        let salt = self.current_salt()?;
        self.persist(&salt)
    }

    fn delete(&mut self, key: &str) -> Result<(), VaultError> {
        self.secrets.remove(key);
        let salt = self.current_salt()?;
        self.persist(&salt)
    }

    fn list(&self) -> Result<Vec<String>, VaultError> {
        Ok(self.secrets.keys().cloned().collect())
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_create_and_read_vault() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Remove the file so EncryptedFileVault creates it fresh
        std::fs::remove_file(&path).unwrap();

        let mut vault = EncryptedFileVault::open(&path, "test-password").unwrap();
        vault.set("API_KEY", "sk-12345").unwrap();

        // Reopen with same password
        let vault2 = EncryptedFileVault::open(&path, "test-password").unwrap();
        assert_eq!(vault2.get("API_KEY").unwrap(), "sk-12345");
    }

    #[test]
    fn test_wrong_password_fails() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).unwrap();

        let mut vault = EncryptedFileVault::open(&path, "correct").unwrap();
        vault.set("KEY", "value").unwrap();

        let err = EncryptedFileVault::open(&path, "wrong").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
    }

    #[test]
    fn test_list_and_delete() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).unwrap();

        let mut vault = EncryptedFileVault::open(&path, "pass").unwrap();
        vault.set("A", "1").unwrap();
        vault.set("B", "2").unwrap();

        let mut keys = vault.list().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["A", "B"]);

        vault.delete("A").unwrap();
        assert!(matches!(vault.get("A"), Err(VaultError::KeyNotFound(_))));

        let keys = vault.list().unwrap();
        assert_eq!(keys, vec!["B"]);
    }

    #[test]
    fn test_key_not_found() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).unwrap();

        let vault = EncryptedFileVault::open(&path, "pass").unwrap();
        let err = vault.get("NONEXISTENT").unwrap_err();
        assert!(matches!(err, VaultError::KeyNotFound(_)));
    }
}
