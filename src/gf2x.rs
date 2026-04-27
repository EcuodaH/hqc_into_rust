use crate::parameters::*;

pub const KARATSUBA_THRESHOLD: u64 = 16;
pub const TMP_BUFFER_WORDS: usize = 16 * VEC_N_SIZE_64;

//multiplication de 2 vecteurs sur GF(2) : calcule r = a * b où a, b sont de len n, r résultat de taille 2*n
fn schoolbook_mul(r: &mut [u64], a: &[u64], b: &[u64], n: usize){
    r.fill(0);
    for i in 0..n {
        let ai = a[i];
        for bit in 0..64 {
            let mask  = ((ai >> bit) & 1u64).wrapping_neg();
            if bit == 0  {
                for j in 0..n {
                    r[i + j] ^= b[j] & mask;
                }
            }else{
                let inv: i32 = 64 - bit;
                for j in 0..n {
                   r[i + j] ^= (b[j] << bit) & mask;
                   r[i + j + 1] ^= (b[j] >> inv) & mask;  
                }
            }
        }
    }
}

fn karatsuba_mul(r: &mut [u64], a: &[u64], b: &[u64], n: usize, tmp_buffer: &mut [u64]){
    if n <= KARATSUBA_THRESHOLD as usize{
        schoolbook_mul(r, a, b, n);
        return;
    }

    let m  = n >> 1;
    let n0  = m;
    let n1  = n - m;

    let (z0, rest) = tmp_buffer.split_at_mut(2 * n);
    let (z2, rest) = rest.split_at_mut(2 * n);
    let (zmid, rest) = rest.split_at_mut(2 * n);
    let (ta, rest) = rest.split_at_mut(n);
    let (tb, child_buffer) = rest.split_at_mut(n);

    karatsuba_mul(z0, a, b, n0, child_buffer);

    karatsuba_mul(z2, &a[m..], &b[m..], n1, child_buffer);

    for i in 0..n1 {
        let loa  = if i < n0 {a[i]}else{0u64};
        let lob  = if i < n0 {b[i]}else{0u64};
        ta[i] = loa ^ a[m + i];
        tb[i] = lob ^ b[m + i];
    }
    karatsuba_mul(zmid, ta, tb, n1, child_buffer);

    r.fill(0);
    for i in 0..(2 * n0){r[i]^= z0[i];}
    for i in 0..(2 * n1){r[2 * m + i] ^= z2[i];}
    for i in 0..(2 * n1){
        let z0i = if i < (2 * n0) {z0[i]}else{0u64};
        let z2i = if i < (2*n1) {z2[i]}else{0u64};
        let mid = zmid[i] ^ z0i ^ z2i;
        r[m+ i] ^= mid;
    }

}

fn reduce(o: &mut [u64], a: &[u64]){
    for i in 0..VEC_N_SIZE_64{
        let r: u64 = a[i + VEC_N_SIZE_64 -1] >> ((PARAM_N & 0x3F) as u32);
        let carry: u64 = a[i + VEC_N_SIZE_64] << ((64 - (PARAM_N & 0x3F)) as u32);
        o[i] = a[i] ^ r ^ carry;
    }
    o[VEC_N_SIZE_64 -1] &= bitmask(PARAM_N, 64);
}

pub fn vect_mul(o: &mut [u64], a1 : &[u64], a2 : &[u64]){
    let mut unreduced  = [0u64; 2 * VEC_N_SIZE_64];
    let mut tmp_buffer  = [0u64; TMP_BUFFER_WORDS];

    karatsuba_mul(&mut unreduced, a1, a2, VEC_N_SIZE_64, &mut tmp_buffer);

    reduce(o, &unreduced);
}