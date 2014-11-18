pub fn encrypt_cbc(f: |&[u8], &[u8]| -> Vec<u8>, plain: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert!(plain.len() % 16 == 0);

    let mut tmp: Vec<u8> = iv.to_vec();
    let mut result: Vec<u8> = Vec::new();
    for chunk in plain.chunks(16) {
        tmp = Vec::from_fn(16, |idx| tmp[idx] ^ chunk[idx]);
        result.push_all(f(tmp.as_slice(), key).as_slice());
    }
    result
}

pub fn decrypt_cbc(f: |&[u8], &[u8]| -> Vec<u8>, plain: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert!(plain.len() % 16 == 0);

    let mut tmp: Vec<u8> = iv.to_vec();
    let mut result: Vec<u8> = Vec::new();
    for chunk in plain.chunks(16) {
        tmp = f(chunk, key)
            .iter()
            .zip(tmp.iter())
            .map(|(&x, &y)| x ^ y)
            .collect();
        result.push_all(tmp.as_slice());
        tmp = chunk.to_vec();
    }
    result
}