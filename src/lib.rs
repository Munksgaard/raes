#![feature(slicing_syntax)]

// Copied from Wikipedia: http://en.wikipedia.org/w/index.php?title=Rijndael_S-box&oldid=626170897
static SBOX: [u8, ..256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16];

// Copied from Wikipedia: http://en.wikipedia.org/w/index.php?title=Rijndael_S-box&oldid=626170897
#[allow(dead_code)]
static INV_SBOX: [u8, ..256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D];


// From www.formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng.swfg
static RCON: [[u8, ..4], ..10] = [
    [0x01, 0, 0, 0], [0x02, 0, 0, 0], [0x04, 0, 0, 0], [0x08, 0, 0, 0],
    [0x10, 0, 0, 0], [0x20, 0, 0, 0], [0x40, 0, 0, 0], [0x80, 0, 0, 0],
    [0x1B, 0, 0, 0], [0x36, 0, 0, 0]];

fn sub_bytes(input: &[u8]) -> Vec<u8> {
    let result: Vec<u8> = input.iter().map(|&x| SBOX[x as uint]).collect();
    return result;
}

#[allow(dead_code)]
fn sub_bytes_inv(input: &[u8]) -> Vec<u8> {
 let result: Vec<u8> = input.iter().map(|&x| INV_SBOX[x as uint]).collect();
    return result;
}

fn shift_rows(input: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), 16);

    let result: Vec<u8> = Vec::from_fn(16, |idx| {
        input[(idx * 4 + idx) % 16]
    });

    result
}

#[allow(dead_code)]
fn shift_rows_inv(input: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), 16);

    let result: Vec<u8> = Vec::from_fn(16, |idx| {
        input[(idx - (4 * idx)) % 16]
    });

    result
}

// Adapted from Wikipedia: http://en.wikipedia.org/w/index.php?title=Rijndael_mix_columns&oldid=606147318#Implementation_example
fn mix_column(input: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), 4);

    let mut a: Vec<u8> = Vec::with_capacity(4);
    let mut b: Vec<u8> = Vec::with_capacity(4);
    let mut h: u8;
    let mut result: Vec<u8> = Vec::with_capacity(4);

    for c in range(0, 4) {
        a.push(input[c]);
        h = ((input[c] as i8) >> 7) as u8;
        b.push(input[c] << 1);
        *b.last_mut().unwrap() = b[c] ^ 0x1B & h;
    }

    result.push(b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]); /* 2 * a0 + a3 + a2 + 3 * a1 */
    result.push(b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]); /* 2 * a1 + a0 + a3 + 3 * a2 */
    result.push(b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]); /* 2 * a2 + a1 + a0 + 3 * a3 */
    result.push(b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]); /* 2 * a3 + a2 + a1 + 3 * a0 */

    result
}

fn mix_columns(input: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), 16);

    let mut result: Vec<u8> = Vec::with_capacity(16);
    for chunk in input.chunks(4) {
        let tmp = mix_column(chunk);
        result.push_all(tmp.as_slice());
    }

    result
}

fn add_round_key(input: &[u8], round_key: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), 16);
    assert_eq!(round_key.len(), 16);

    Vec::from_fn(16, |idx| input[idx] ^ round_key[idx])
}

fn round_key(prev: &[u8], rcon: &[u8]) -> Vec<u8> {
    assert_eq!(prev.len(), 16);
    assert_eq!(rcon.len(), 4);

    let mut result = Vec::from_elem(16, 0u8);
    for idx in range(0, 16) {
        *result.get_mut(idx) = if idx < 4 {
            SBOX[prev[((1 + idx) % 4) + 12] as uint] ^ prev[idx] ^ rcon[idx]
        } else {
            prev[idx] ^ result[idx-4]
        };
    }

    result
}

#[allow(dead_code)]
fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(plaintext.len(), 16);
    assert_eq!(key.len(), 16);

    let mut tmp = add_round_key(plaintext, key);
    let mut key = key.to_vec();

    for round in range(0u, 9) {
        tmp = sub_bytes(tmp.as_slice());
        tmp = shift_rows(tmp.as_slice());
        tmp = mix_columns(tmp.as_slice());
        key = round_key(key.as_slice(), &RCON[round]);
        tmp = add_round_key(tmp.as_slice(), key.as_slice());
    }

    tmp = sub_bytes(tmp.as_slice());
    tmp = shift_rows(tmp.as_slice());
    key = round_key(key.as_slice(), &RCON[9]);
    tmp = add_round_key(tmp.as_slice(), key.as_slice());

    tmp
}

#[cfg(test)]
mod test {
    use super::SBOX;
    use super::sub_bytes;
    use super::sub_bytes_inv;
    use super::shift_rows;
    use super::shift_rows_inv;
    use super::mix_column;
    use super::mix_columns;
    use super::add_round_key;
    use super::round_key;
    use super::encrypt;

    #[test]
    fn test_sbox() {
        assert_eq!(SBOX[0xCF], 0x8A);
        assert_eq!(SBOX[0x19], 0xD4);
    }

    #[test]
    fn test_sub_bytes() {
        let input = vec![0x19u8, 0xA0, 0x9A, 0xE9];
        let output = vec![0xD4u8, 0xE0, 0xB8, 0x1E];
        assert_eq!(sub_bytes(input.as_slice()), output);
    }

    #[test]
    fn test_sub_bytes_inv() {
        let input = &[0xD4u8, 0xE0, 0xB8, 0x1E];
        let output = vec![0x19u8, 0xA0, 0x9A, 0xE9];
        assert_eq!(sub_bytes_inv(input), output);
    }

    #[test]
    fn test_shift_rows() {
        let input = &[0xD4, 0x27, 0x11, 0xAE,
                      0xE0, 0xBF, 0x98, 0xF1,
                      0xB8, 0xB4, 0x5D, 0xE5,
                      0x1E, 0x41, 0x52, 0x30];
        let expected = vec![0xD4, 0xBF, 0x5D, 0x30,
                            0xE0, 0xB4, 0x52, 0xAE,
                            0xB8, 0x41, 0x11, 0xF1,
                            0x1E, 0x27, 0x98, 0xE5];
        assert_eq!(shift_rows(input), expected);
    }

    #[test]
    fn test_shift_rows_inv() {
        let input = &[0xD4, 0xBF, 0x5D, 0x30,
                      0xE0, 0xB4, 0x52, 0xAE,
                      0xB8, 0x41, 0x11, 0xF1,
                      0x1E, 0x27, 0x98, 0xE5];
        let expected = vec![0xD4, 0x27, 0x11, 0xAE,
                            0xE0, 0xBF, 0x98, 0xF1,
                            0xB8, 0xB4, 0x5D, 0xE5,
                            0x1E, 0x41, 0x52, 0x30];
        assert_eq!(shift_rows_inv(input), expected);
    }

    #[test]
    fn test_mix_column() {
        let input = vec![0xDB, 0x13, 0x53, 0x45];
        let expected = vec![142, 77, 161, 188];
        assert_eq!(mix_column(input.as_slice()), expected);

        let input = vec![0xD4, 0xBF, 0x5D, 0x30];
        let expected = vec![0x04, 0x66, 0x81, 0xE5];
        assert_eq!(mix_column(input.as_slice()), expected);
    }

    #[test]
    fn test_mix_columns() {
        let input = &[0xD4, 0xBF, 0x5D, 0x30,
                      0xE0, 0xB4, 0x52, 0xAE,
                      0xB8, 0x41, 0x11, 0xF1,
                      0x1E, 0x27, 0x98, 0xE5];
        let expected = vec![0x04, 0x66, 0x81, 0xE5,
                            0xE0, 0xCB, 0x19, 0x9A,
                            0x48, 0xF8, 0xD3, 0x7A,
                            0x28, 0x06, 0x26, 0x4C];
        assert_eq!(mix_columns(input), expected);
    }

    #[test]
    fn test_add_round_key() {
        let input = &[0x04, 0x66, 0x81, 0xE5,
                      0xE0, 0xCB, 0x19, 0x9A,
                      0x48, 0xF8, 0xD3, 0x7A,
                      0x28, 0x06, 0x26, 0x4C];
        let round_key = &[0xA0, 0xFA, 0xFE, 0x17,
                          0x88, 0x54, 0x2c, 0xB1,
                          0x23, 0xA3, 0x39, 0x39,
                          0x2A, 0x6C, 0x76, 0x05];
        let expected = vec![0xA4, 0x9C, 0x7F, 0xF2,
                            0x68, 0x9F, 0x35, 0x2B,
                            0x6B, 0x5B, 0xEA, 0x43,
                            0x02, 0x6A, 0x50, 0x49];

        assert_eq!(add_round_key(input, round_key), expected);
    }

    #[test]
    fn test_round_key() {
        let input = &[0x2B, 0x7E, 0x15, 0x16,
                      0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88,
                      0x09, 0xCF, 0x4F, 0x3C];
        let rcon1 = &[0x01, 0x00, 0x00, 0x00];
        let expected = vec![0xA0, 0xFA, 0xFE, 0x17,
                            0x88, 0x54, 0x2C, 0xB1,
                            0x23, 0xA3, 0x39, 0x39,
                            0x2A, 0x6C, 0x76, 0x05];
        let res1 = round_key(input, rcon1);
        assert_eq!(res1, expected);

        let rcon2 = &[0x02, 0x00, 0x00, 0x00];
        let expected2 = vec![0xF2, 0xC2, 0x95, 0xF2,
                             0x7A, 0x96, 0xB9, 0x43,
                             0x59, 0x35, 0x80, 0x7A,
                             0x73, 0x59, 0xF6, 0x7F];
        assert_eq!(round_key(res1.as_slice(), rcon2), expected2);
    }

    #[test]
    // Example from  www.formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng.swfg
    fn test_encrypt() {
        let plain = &[0x32, 0x43, 0xF6, 0xA8,
                      0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2,
                      0xE0, 0x37, 0x07, 0x34];
        let key = &[0x2B, 0x7E, 0x15, 0x16,
                    0x28, 0xAE, 0xD2, 0xA6,
                    0xAB, 0xF7, 0x15, 0x88,
                    0x09, 0xCF, 0x4F, 0x3C];
        let expected = vec![0x39, 0x25, 0x84, 0x1D,
                            0x02, 0xDC, 0x09, 0xFB,
                            0xDC, 0x11, 0x85, 0x97,
                            0x19, 0x6a, 0x0B, 0x32];
        assert_eq!(encrypt(plain, key), expected);

        let plain = &[0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00];
        let key = &[0x80, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00];
        let expected = vec![0x0e, 0xdd, 0x33, 0xd3,
                            0xc6, 0x21, 0xe5, 0x46,
                            0x45, 0x5b, 0xd8, 0xba,
                            0x14, 0x18, 0xbe, 0xc8];
        assert_eq!(encrypt(plain, key), expected);

        let key = &[0xc0, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00];
        let plain = &[0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00];
        let expected = vec![0x4b, 0xc3, 0xf8, 0x83,
                            0x45, 0x0c, 0x11, 0x3c,
                            0x64, 0xca, 0x42, 0xe1,
                            0x11, 0x2a, 0x9e, 0x87];
        assert_eq!(encrypt(plain, key), expected);
    }
}
