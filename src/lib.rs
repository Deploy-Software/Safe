use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use argon2::{self, Config};

fn make_cipher(master_password: &str, salt: &str) -> Aes256Gcm {
    let config = Config::default();
    let hash = argon2::hash_encoded(master_password.as_bytes(), salt.as_bytes(), &config).unwrap();
    let encoded = base64::encode_config(&hash, base64::CRYPT)
        .split_at(32)
        .0
        .to_string();
    let key = GenericArray::from_slice(encoded.as_bytes());
    Aes256Gcm::new(key)
}

pub fn encrypt(master_password: &str, salt: &str, local_password: &str) -> String {
    let cipher = make_cipher(master_password, salt);
    let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(nonce, local_password.as_bytes().as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
    base64::encode_config(ciphertext.clone(), base64::URL_SAFE_NO_PAD)
}

pub fn decrypt(master_password: &str, salt: &str, hashed: &str) -> String {
    let cipher = make_cipher(master_password, salt);
    let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
    let decoded = base64::decode_config(hashed, base64::URL_SAFE_NO_PAD).unwrap();
    let plaintext = cipher
        .decrypt(nonce, decoded.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    String::from_utf8(plaintext).unwrap()
}
