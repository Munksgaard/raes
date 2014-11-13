mod aes;
mod ecb;


pub enum Cipher {
    AES,
}

pub enum Mode {
    ECB,
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
    }
}
