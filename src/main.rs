use safe::Safe;
use std::fs::File;
use std::io::prelude::*;

const FILENAME: &str = "safe.json";
const MASTER_PASSWORD: &str = "heyo";

fn main() {
    let mut file = match File::open(FILENAME) {
        Ok(file) => file,
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound => {
                let mut temp_file = File::create(FILENAME).unwrap();
                let safe = Safe::new(MASTER_PASSWORD.to_string()).unwrap();
                temp_file
                    .write_all(safe.json().unwrap().as_bytes())
                    .unwrap();
                File::open(FILENAME).unwrap()
            }
            _ => panic!(error.to_string()),
        },
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let safe = Safe::from(contents).unwrap();
    let output = safe.json().unwrap();
    println!("{}", output);
    //let hash = encrypt(master_password, salt, "heyo");
    //let decrypted = decrypt(master_password, salt, &hash);
    //println!("{}", decrypted);
}
