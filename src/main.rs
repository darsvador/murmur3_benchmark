use fasthash::murmur3::hash32_with_seed as hash_with_seed;
use openssl::rand::rand_bytes;
use std::io::Cursor;
use murmur3::murmur3_32;
use std::num::Wrapping;
pub trait Murmur3 {
    fn murmur_hash<T: AsRef<[u8]>>(self, bytes: T) -> u32;
}

impl Murmur3 for u32 {
    fn murmur_hash<T: AsRef<[u8]>>(self, bytes: T) -> u32 {
        let ptr = bytes.as_ref().as_ptr();
        let len = bytes.as_ref().len();
        let mut h = Wrapping(self);
        let c1 = Wrapping(0xcc9e2d51u32);
        let c2 = Wrapping(0x1b873593u32);

        unsafe {
            let (block, left): (&[u32], &[u8]) = {
                let (us_len, ts_len) = (len / 4, len & 3);
                (
                    std::slice::from_raw_parts(ptr as *const u32, us_len),
                    std::slice::from_raw_parts(ptr.add(len - ts_len), ts_len),
                )
            };
            for &k in block.iter() {
                let mut k = Wrapping(k) * c1;
                k = (k << 15) | (k >> 17);
                k *= c2;
                h ^= k;
                h = (h << 13) | (h >> 19);
                h = h * Wrapping(5) + Wrapping(0xe6546b64);
            }
            let mut k = Wrapping(0u32);
            match left.len() {
                3 => {
                    k ^= Wrapping(left[2] as u32) << 16;
                    k ^= Wrapping(left[1] as u32) << 8;
                    k ^= Wrapping(left[0] as u32);
                    k *= c1;
                    k = (k << 15) | (k >> 17);
                    k *= c2;
                    h ^= k;
                }
                2 => {
                    k ^= Wrapping(left[1] as u32) << 8;
                    k ^= Wrapping(left[0] as u32);
                    k *= c1;
                    k = (k << 15) | (k >> 17);
                    k *= c2;
                    h ^= k;
                }
                1 => {
                    k ^= Wrapping(left[0] as u32);
                    k *= c1;
                    k = (k << 15) | (k >> 17);
                    k *= c2;
                    h ^= k;
                }
                0 => {}
                _ => core::hint::unreachable_unchecked(),
            }
            h ^= Wrapping(len as u32);
            h ^= h >> 16;
            h *= Wrapping(0x85ebca6b);
            h ^= h >> 13;
            h *= Wrapping(0xc2b2ae35);
            h ^= h >> 16;
        }
        h.0
    }
}

fn main() {
    use std::time::Instant;
    let mut buf = [0; 85];
    rand_bytes(&mut buf).unwrap();
    let run_times = 100000000;
    let t0: u128;
    let t1: u128;
    let t2: u128;
    let now = Instant::now();
    let mut h0 = 0u32;
    for _ in 0..run_times {
        h0 = h0.murmur_hash(&buf);
    }
    t0 = now.elapsed().as_millis();
    let now = Instant::now();
    let mut h1 = 0u32;
    for _ in 0..run_times {
        h1 = hash_with_seed(&buf, h1);
    }
    t1 = now.elapsed().as_millis();
    let now = Instant::now();
    let mut h2 = 0u32;
    for _ in 0..run_times {
        h2 = murmur3_32(&mut Cursor::new(buf), h2).unwrap();
    }
    t2 = now.elapsed().as_millis();
    if h1 == h0 && h0==h2{
        println!("ffi time cost:{}ms, native rust time cost:{}ms, murmur3 crate time cost:{}ms", t1, t0, t2);
        println!(
            "ffi is faster than native rust:{}%",
            ((t0 as f64 - t1 as f64) / t1 as f64) * 100.0
        );
    }
}
