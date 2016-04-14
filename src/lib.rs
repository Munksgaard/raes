#![feature(step_by)]

extern crate getopts;

pub mod aes;
pub mod ecb;
pub mod cbc;
pub mod ctr;
mod util;

#[cfg(test)]
mod test {
    use super::{aes, ecb, cbc, ctr};

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
        let iv = &[0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0];
        let expected = vec![0x39, 0x25, 0x84, 0x1D,
                            0x02, 0xDC, 0x09, 0xFB,
                            0xDC, 0x11, 0x85, 0x97,
                            0x19, 0x6a, 0x0B, 0x32];
        assert_eq!(cbc::encrypt(aes::encrypt, plain, key, iv), expected);
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
        let iv = &[0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0];
        let expected = vec![0x32, 0x43, 0xF6, 0xA8,
                            0x88, 0x5A, 0x30, 0x8D,
                            0x31, 0x31, 0x98, 0xA2,
                            0xE0, 0x37, 0x07, 0x34];
        assert_eq!(cbc::decrypt(aes::decrypt, cipher, key, iv), expected);
    }

    #[test]
    fn encrypt_and_decrypt_cbc() {
        let plain = b"Yellow submarineYellow submarine";

        let key = &[21, 74, 153, 147,
                    244, 100, 141, 128,
                    30, 176, 207, 176,
                    202, 11, 105, 107];

        let iv = &[0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0];

        let encrypted = cbc::encrypt(aes::encrypt, plain, key, iv);
        assert_eq!(cbc::decrypt(aes::decrypt, &encrypted, key, iv), plain);
    }

    #[test]
    fn encrypt_and_decrypt_ecb() {
        let plain = b"Yellow submarineYellow submarine";

        let key = &[21, 74, 153, 147,
                    244, 100, 141, 128,
                    30, 176, 207, 176,
                    202, 11, 105, 107];

        let iv = &[0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0];

        let encrypted = ecb::ecb(aes::encrypt, plain, key);
        assert_eq!(ecb::ecb(aes::decrypt, &encrypted, key), plain);
    }

    #[test]
    fn encrypt_and_decrypt_ctr() {
        let plain: &[u8] = b"Mary had a little lamb. IH AI IH AI OOOOH! And it was CUTE! I think....";
        let key = b"YELLOW SUBMARINE";
        let encrypted = ctr::ctr(aes::encrypt, plain, key, 0);
        let decrypted = ctr::ctr(aes::encrypt, &encrypted, key, 0);

        assert_eq!(decrypted, plain);
    }
}
