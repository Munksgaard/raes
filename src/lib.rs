mod aes;
mod ecb;
mod cbc;

pub enum Cipher {
    AES,
}

pub enum Mode {
    ECB,
    CBC,
}

#[allow(dead_code)]
pub fn encrypt(cipher: Cipher, mode: Mode, input: &[u8], key: &[u8], iv: Option<Vec<u8>>) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert!(input.len() % 16 == 0);

    let f = match cipher {
        AES => aes::encrypt,
    };

    match mode {
        ECB => ecb::ecb(|x,y| f(x,y), input, key),
        CBC => cbc::encrypt_cbc(|x,y| f(x,y), input, key, iv.unwrap().as_slice()),
    }
}

#[allow(dead_code)]
pub fn decrypt(cipher: Cipher, mode: Mode, input: &[u8], key: &[u8], iv: Option<Vec<u8>>) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert!(input.len() % 16 == 0);

    let f = match cipher {
        AES => aes::decrypt,
    };

    match mode {
        ECB => ecb::ecb(|x,y| f(x,y), input, key),
        CBC => cbc::decrypt_cbc(|x,y| f(x,y), input, key, iv.unwrap().as_slice()),
    }
}
