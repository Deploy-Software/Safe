use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use argon2::{self, Config};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct StorageType {
    name: String,
    data: String,
}

#[derive(Serialize, Deserialize)]
enum DataType {
    Encrypted(StorageType),
    Unencrypted(StorageType),
}

type Item = Vec<DataType>;

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
    EncryptionError,
    WrongPassword,
    HashInvalid,
    HashToStringFailure,
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
        let salt = "randomsalt".to_string();
        let hash =
            argon2::hash_encoded(master_password.as_bytes(), salt.as_bytes(), &config).unwrap();
        let encoded = base64::encode_config(&hash, base64::CRYPT);

        Ok(Self {
            salt,
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

    fn encrypt(&self, master_password: &str, to_encrypt: &str) -> Result<String, SafeErrorKind> {
        let decoded_hash = match base64::decode_config(&self.hash, base64::CRYPT) {
            Ok(decoded) => decoded,
            Err(_error) => return Err(SafeErrorKind::HashInvalid),
        };
        let decoded_hash_string = match String::from_utf8(decoded_hash) {
            Ok(string) => string,
            Err(_error) => return Err(SafeErrorKind::HashToStringFailure),
        };
        let matches =
            argon2::verify_encoded(&decoded_hash_string, master_password.as_bytes().as_ref())
                .unwrap();
        if !matches {
            return Err(SafeErrorKind::WrongPassword);
        }
        let cipher = self.make_cipher(master_password);
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = match cipher.encrypt(nonce, to_encrypt.as_bytes().as_ref()) {
            Ok(ciphertext) => ciphertext,
            Err(_error) => {
                return Err(SafeErrorKind::EncryptionError);
            }
        };
        Ok(base64::encode_config(
            ciphertext.clone(),
            base64::URL_SAFE_NO_PAD,
        ))
    }

    fn decrypt(&self, master_password: &str, hashed: &str) -> String {
        let cipher = self.make_cipher(master_password);
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let decoded = base64::decode_config(hashed, base64::URL_SAFE_NO_PAD).unwrap();
        let plaintext = cipher
            .decrypt(nonce, decoded.as_ref())
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        String::from_utf8(plaintext).unwrap()
    }

    pub fn new_item(&mut self, title: String) -> Result<(), SafeErrorKind> {
        self.items.insert(title, vec![]);
        Ok(())
    }

    pub fn add_encrypted_data(
        &mut self,
        master_password: String,
        title: String,
        data_name: String,
        data_value: String,
    ) -> Result<(), SafeErrorKind> {
        let encrypted_value = self.encrypt(&master_password, &data_value)?;
        if let Some(item) = self.items.get_mut(&title) {
            let new_item = DataType::Encrypted(StorageType {
                name: data_name,
                data: encrypted_value,
            });
            item.push(new_item);
            Ok(())
        } else {
            Err(SafeErrorKind::NotFound)
        }
    }
}
