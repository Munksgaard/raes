pub fn encrypt<F>(f: F, plain: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8>
where F: Fn(&[u8], &[u8]) -> Vec<u8>
{
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert_eq!(plain.len() % 16, 0);

    let mut iv = iv.to_vec();
    let mut result: Vec<u8> = Vec::new();

    for chunk in plain.chunks(16) {
        let mut tmp = Vec::new();
        for (x, y) in chunk.iter().zip(iv) {
            tmp.push(x ^ y);
        }

        let encrypted = f(&tmp, key);

        result.extend_from_slice(&encrypted);
        iv = encrypted;
    }
    result
}

pub fn decrypt<F>(f: F, cipher: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8>
where F: Fn(&[u8], &[u8]) -> Vec<u8>
{
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert_eq!(cipher.len() % 16, 0);

    let mut iv = iv.to_vec();

    let mut result: Vec<u8> = Vec::new();

    for chunk in cipher.chunks(16) {
        let tmp = f(chunk, key);

        for (x, y) in tmp.iter().zip(iv) {
            result.push(x ^ y);
        }

        iv = chunk.to_vec();
    }

    result
}
