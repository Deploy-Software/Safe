use safe::{decrypt, encrypt};
use std::fs::File;
use std::io::prelude::*;

const FILENAME: &str = "safe.json";

fn main() {
    let mut file = match File::open(FILENAME) {
        Ok(file) => file,
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound => {
                File::create(FILENAME).unwrap();
                File::open(FILENAME).unwrap()
            }
            _ => panic!(error.to_string()),
        },
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let master_password = "password";
    let salt = "randomsalt";
    let hash = encrypt(master_password, salt, "heyo");
    let decrypted = decrypt(master_password, salt, &hash);
    println!("{}", decrypted);
}
