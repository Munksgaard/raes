pub fn ecb<F>(f: F, plain: &[u8], key: &[u8]) -> Vec<u8>
where F: Fn(&[u8], &[u8]) -> Vec<u8>
{
    assert_eq!(key.len(), 16);
    assert_eq!(plain.len() % 16, 0);

    let mut result: Vec<u8> = Vec::new();
    for chunk in plain.chunks(16) {
        result.extend(f(chunk, key));
    }
    result
}
