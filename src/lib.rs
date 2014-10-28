#![feature(slicing_syntax)]

mod aes;

#[allow(dead_code)]
pub fn encode_aes_ecb(plain: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert!(plain.len() % 16 == 0);

    let mut result: Vec<u8> = Vec::new();
    for chunk in plain.chunks(16) {
        result.push_all(aes::encrypt(chunk, key).as_slice());
    }
    result
}

#[allow(dead_code)]
pub fn decode_aes_ecb(cipher: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert!(cipher.len() % 16 == 0);

    let mut result: Vec<u8> = Vec::new();
    for chunk in cipher.chunks(16) {
        result.push_all(aes::decrypt(chunk, key).as_slice());
    }
    result
}
