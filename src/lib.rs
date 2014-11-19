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
        Cipher::AES => aes::encrypt,
    };

    match mode {
        Mode::ECB => ecb::ecb(|x,y| f(x,y), input, key),
        Mode::CBC => cbc::encrypt_cbc(|x,y| f(x,y), input, key, iv.unwrap().as_slice()),
    }
}

#[allow(dead_code)]
pub fn decrypt(cipher: Cipher, mode: Mode, input: &[u8], key: &[u8], iv: Option<Vec<u8>>) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert!(input.len() % 16 == 0);

    let f = match cipher {
        Cipher::AES => aes::decrypt,
    };

    match mode {
        Mode::ECB => ecb::ecb(|x,y| f(x,y), input, key),
        Mode::CBC => cbc::decrypt_cbc(|x,y| f(x,y), input, key, iv.unwrap().as_slice()),
    }
}

// FIXME: More comprehensive tests (these only test the first block)
// FIXME: Tests for ECB.
#[cfg(test)]
mod test {
    use super::{encrypt,
                decrypt,
                Cipher,
                Mode,
    };

    #[test]
    fn test_encrypt_cbc() {
        let plain = &[0x32, 0x43, 0xF6, 0xA8,
                      0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2,
                      0xE0, 0x37, 0x07, 0x34];
        let key = &[0x2B, 0x7E, 0x15, 0x16,
                    0x28, 0xAE, 0xD2, 0xA6,
                    0xAB, 0xF7, 0x15, 0x88,
                    0x09, 0xCF, 0x4F, 0x3C];
        let iv = vec![0, 0, 0, 0,
                      0, 0, 0, 0,
                      0, 0, 0, 0,
                      0, 0, 0, 0];
        let expected = vec![0x39, 0x25, 0x84, 0x1D,
                            0x02, 0xDC, 0x09, 0xFB,
                            0xDC, 0x11, 0x85, 0x97,
                            0x19, 0x6a, 0x0B, 0x32];
        assert_eq!(encrypt(Cipher::AES, Mode::CBC, plain, key, Some(iv)), expected);
    }

    #[test]
    fn test_decrypt_cbc() {
        let cipher = &[0x39, 0x25, 0x84, 0x1D,
                       0x02, 0xDC, 0x09, 0xFB,
                       0xDC, 0x11, 0x85, 0x97,
                       0x19, 0x6a, 0x0B, 0x32];
        let key = &[0x2B, 0x7E, 0x15, 0x16,
                    0x28, 0xAE, 0xD2, 0xA6,
                    0xAB, 0xF7, 0x15, 0x88,
                    0x09, 0xCF, 0x4F, 0x3C];
        let iv = vec![0, 0, 0, 0,
                      0, 0, 0, 0,
                      0, 0, 0, 0,
                      0, 0, 0, 0];
        let expected = vec![0x32, 0x43, 0xF6, 0xA8,
                            0x88, 0x5A, 0x30, 0x8D,
                            0x31, 0x31, 0x98, 0xA2,
                            0xE0, 0x37, 0x07, 0x34];
        assert_eq!(decrypt(Cipher::AES, Mode::CBC, cipher, key, Some(iv)), expected);
    }
}
