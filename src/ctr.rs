/* C function to change endianness for byte swap in an unsigned 32-bit integer */

//uint32_t ChangeEndianness(uint32_t value)
//{
//    uint32_t result = 0;
//    result |= (value & 0x000000FF) << 24;
//    result |= (value & 0x0000FF00) << 8;
//    result |= (value & 0x00FF0000) >> 8;
//    result |= (value & 0xFF000000) >> 24;
//    return result;
//}

fn u64_to_bytes(value: u64) -> Vec<u8> {
    let mut buf = Vec::new();

    for i in 0..8 {
        let mask = 0xFF << (i * 8);
        let byte = (value & mask) >> (i * 8);
        buf.push(byte as u8);
    }

    buf
}

#[test]
fn test_u64_to_bytes() {
    let n = 0x1234567890ABCDEF;
    let bytes = u64_to_bytes(n);
    let expected: &[u8] = &[0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
    assert_eq!(bytes, expected);

    let n = 0xAAAA;
    let bytes = u64_to_bytes(n);
    let expected: &[u8] = &[0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(bytes, expected);
}

fn ctr_block<F>(f: F, plain: &[u8], key: &[u8], nonce: u64, counter: u64) -> Vec<u8>
    where F: Fn(&[u8], &[u8]) -> Vec<u8> {
    assert!(plain.len() <= 16);
    assert!(key.len() <= 16);

    let mut buf = u64_to_bytes(nonce);
    let tmp = u64_to_bytes(counter);
    buf.extend_from_slice(&tmp);

    let cipher = f(&buf, key);

    let mut result = Vec::new();

    for (x, y) in cipher.iter().zip(plain) {
        result.push(x ^ y);
    }

    result
}

pub fn ctr<F>(f: F, plain: &[u8], key: &[u8], nonce: u64) -> Vec<u8>
    where F: Fn(&[u8], &[u8]) -> Vec<u8> {

    assert_eq!(16, key.len());

    let mut buf = Vec::new();

    for (count, block) in plain.chunks(16).enumerate() {
        let tmp = ctr_block(&f, block, key, nonce, count as u64);
        buf.extend_from_slice(&tmp);
    }

    buf
}
