use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use argon2::{self, Config};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
enum UnencryptedStorageType {
    Username(String),
    Link(String),
}

#[derive(Serialize, Deserialize)]
enum EncryptedStorageType {
    Password(String),
}

#[derive(Serialize, Deserialize)]
enum DataType {
    Encrypted(EncryptedStorageType),
    Unencrypted(UnencryptedStorageType),
}

#[derive(Serialize, Deserialize)]
struct Data {
    name: String,
    data: DataType,
}

#[derive(Serialize, Deserialize)]
struct Item {
    data: Vec<Data>,
}

#[derive(Serialize, Deserialize)]
pub struct Safe {
    salt: String,
    hash: String,
    items: HashMap<String, Item>,
}

#[derive(Debug)]
pub enum SafeErrorKind {
    SomethingWrong,
    NotFound,
}

impl Safe {
    pub fn from(raw_json: String) -> Result<Safe, SafeErrorKind> {
        Ok(serde_json::from_str::<Self>(&raw_json).unwrap())
    }

    pub fn json(&self) -> Result<String, SafeErrorKind> {
        Ok(serde_json::to_string(self).unwrap())
    }

    pub fn new(master_password: String) -> Result<Safe, SafeErrorKind> {
        let config = Config::default();
        let salt = "randomsalt";
        let hash =
            argon2::hash_encoded(master_password.as_bytes(), salt.as_bytes(), &config).unwrap();
        let encoded = base64::encode_config(&hash, base64::CRYPT);

        Ok(Self {
            salt: String::from("hey"),
            hash: encoded,
            items: HashMap::new(),
        })
    }

    fn make_cipher(&self, master_password: &str) -> Aes256Gcm {
        let config = Config::default();
        let hash = argon2::hash_encoded(master_password.as_bytes(), self.salt.as_bytes(), &config)
            .unwrap();
        let encoded = base64::encode_config(&hash, base64::CRYPT)
            .split_at(32)
            .0
            .to_string();
        let key = GenericArray::from_slice(encoded.as_bytes());
        Aes256Gcm::new(key)
    }

    pub fn encrypt(&self, master_password: &str, local_password: &str) -> String {
        let cipher = self.make_cipher(master_password);
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(nonce, local_password.as_bytes().as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
        base64::encode_config(ciphertext.clone(), base64::URL_SAFE_NO_PAD)
    }

    pub fn decrypt(&self, master_password: &str, hashed: &str) -> String {
        let cipher = self.make_cipher(master_password);
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let decoded = base64::decode_config(hashed, base64::URL_SAFE_NO_PAD).unwrap();
        let plaintext = cipher
            .decrypt(nonce, decoded.as_ref())
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        String::from_utf8(plaintext).unwrap()
    }

    pub fn new_item(&mut self, title: String) -> Result<(), SafeErrorKind> {
        self.items.insert(title, Item { data: vec![] });
        Ok(())
    }

    pub fn new_data(&mut self, title: String) -> Result<(), SafeErrorKind> {
        if let Some(_item) = self.items.get(&title) {
            Ok(())
        } else {
            Err(SafeErrorKind::NotFound)
        }
    }
}
