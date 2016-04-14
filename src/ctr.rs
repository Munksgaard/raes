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

fn print_hex(title: &str, bytes: &[u8]) {
    println!("{}:", title);
    for chunk in bytes.chunks(16) {
        for byte in chunk {
            print!("{:02X} ", byte);
        }
        println!("");
    }
    println!("");
}

fn endian_swap(value: u64) -> u64 {
    let mut result = 0;
    result |= (value & 0x00_00_00_00_00_00_00_FF) << 56;
    result |= (value & 0x00_00_00_00_00_00_FF_00) << 40;
    result |= (value & 0x00_00_00_00_00_FF_00_00) << 24;
    result |= (value & 0x00_00_00_00_FF_00_00_00) << 8;
    result |= (value & 0x00_00_00_FF_00_00_00_00) >> 8;
    result |= (value & 0x00_00_FF_00_00_00_00_00) >> 24;
    result |= (value & 0x00_FF_00_00_00_00_00_00) >> 40;
    result |= (value & 0xFF_00_00_00_00_00_00_00) >> 56;

    result
}

#[test]
fn test_endian_swap() {
    let n = 0x1234567890ABCDEF;
    assert_eq!(n, endian_swap(endian_swap(n)));

    assert_eq!(0xEFCDAB9078563412, endian_swap(n));
}

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
    let mut count = 0;
    let mut buf = Vec::new();

    for block in plain.chunks(16) {
        let tmp = ctr_block(&f, block, key, nonce, count);
        buf.extend_from_slice(&tmp);
        count += 1;
    }

    buf
}

fn main() {
    // let n = 0x0123456789abcdef;
    // let n_ = endian_swap(n);
    // println!("{:016X} -> {:016X}", n, n_);

    // let v1 = u64_to_bytes(n);
    // print_hex("v1", &v1);
    // let v2 = u64_to_bytes(n_);
    // print_hex("v2", &v2);

    // let s = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    // let cipher = base64::decode(s);

    // let plain = ctr(raes::aes::encrypt, &cipher, 0);

    // print_hex("plain", &plain);

    // println!("{}", String::from_utf8(plain).unwrap());

    // let s = b"Mary had a little lamb, IH AI IH AI OH! And the lamb was cute. I think?";
    // let cipher = ctr(raes::aes::encrypt, s, 0);

    // let plain = ctr(raes::aes::encrypt, &cipher, 0);

    // println!("{}", String::from_utf8(plain).unwrap());
}
