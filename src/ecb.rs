pub fn ecb(f: |&[u8], &[u8]| -> Vec<u8>, plain: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    assert!(plain.len() % 16 == 0);

    let mut result: Vec<u8> = Vec::new();
    for chunk in plain.chunks(16) {
        result.push_all(f(chunk, key).as_slice());
    }
    result
}
