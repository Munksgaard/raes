pub fn vec_from_fn<T, F>(size: usize, f: F) -> Vec<T>
  where F: Fn(usize) -> T
{
    let mut result = Vec::with_capacity(size);
    for idx in 0..size {
        result.push(f(idx));
    }
    result
}
