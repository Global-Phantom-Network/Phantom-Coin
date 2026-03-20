use core::cmp::Ordering;

pub fn u256_words_le_from_be_bytes(x: &[u8; 32]) -> [u64; 4] {
    fn read_u64_be(slice: &[u8]) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(slice);
        u64::from_be_bytes(b)
    }

    [
        read_u64_be(&x[24..32]),
        read_u64_be(&x[16..24]),
        read_u64_be(&x[8..16]),
        read_u64_be(&x[0..8]),
    ]
}

pub fn u256_be_bytes_from_words_le(words: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&words[3].to_be_bytes());
    out[8..16].copy_from_slice(&words[2].to_be_bytes());
    out[16..24].copy_from_slice(&words[1].to_be_bytes());
    out[24..32].copy_from_slice(&words[0].to_be_bytes());
    out
}

pub fn mul_u256_by_u64_to_u320_le(a: [u64; 4], m: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for (ai, oi) in a.iter().zip(out.iter_mut()) {
        let prod = (*ai as u128) * (m as u128) + carry;
        *oi = prod as u64;
        carry = prod >> 64;
    }
    if let Some(last) = out.last_mut() {
        *last = carry as u64;
    }
    out
}

pub fn div_u320_by_u64_to_u320_le(n: [u64; 5], d: u64) -> [u64; 5] {
    if d == 0 {
        return [0u64; 5];
    }
    let mut q = [0u64; 5];
    let mut rem: u128 = 0;
    for (ni, qi) in n.iter().rev().zip(q.iter_mut().rev()) {
        let cur = (rem << 64) | (*ni as u128);
        *qi = (cur / (d as u128)) as u64;
        rem = cur % (d as u128);
    }
    q
}

pub fn cmp_u320_le(a: &[u64; 5], b: &[u64; 5]) -> Ordering {
    for (aw, bw) in a.iter().rev().zip(b.iter().rev()) {
        let ord = aw.cmp(bw);
        if !ord.is_eq() {
            return ord;
        }
    }
    Ordering::Equal
}

pub fn u320_to_u256_be_bytes(x: [u64; 5]) -> Option<[u8; 32]> {
    if x[4] != 0 {
        return None;
    }
    Some(u256_be_bytes_from_words_le([x[0], x[1], x[2], x[3]]))
}

pub fn is_zero_hash(h: &[u8; 32]) -> bool {
    h.iter().all(|b| *b == 0)
}
