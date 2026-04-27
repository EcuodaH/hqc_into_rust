use crate::parameters::*;

const GF_REDUCTION_TAPS: [u16; 3] = [4, 3, 2];

pub fn gf_reduce(mut x: u16) -> u16{
    let reduction_steps: usize = 2;
    let gf_reduction_tap_count: usize = 3;

    for _ in 0..reduction_steps{
        let mut modval: u16 = x >> PARAM_M;
        x &= (1 << PARAM_M) - 1;
        x ^= modval;

        let mut z1: u16 = 0u16;
        for j in (1..=gf_reduction_tap_count).rev(){
            let z2: u16 = GF_REDUCTION_TAPS[j - 1];
            let dist = z2 - z1;
            modval <<= dist as u32;
            x ^= modval;
            z1 = z2;
        }
    }
    x
}

pub fn gf_caryless_mul(c: &mut [u8], a: u8, b: u8){
    let mut g: u16 = 0u16;
    let mut u:[u16; 4] = [0u16; 4];

    u[0] = 0;
    u[1] = (b as u16 ) & ((1u16 << 7) - 1u16);
    u[2] = u[1] << 1;
    u[3] = u[2] ^ u[1];

    let tmp1:u16  = (a as u16) & 3u16;

    for i in 0..4 {
        let tmp2 = tmp1.wrapping_sub(i as u16);
        let is_zero = (tmp2 as u32 | (tmp2 as u32).wrapping_neg()) >> 31;
        let mask = (1u16.wrapping_sub(is_zero as u16)).wrapping_neg();
        g ^= u[i] & mask;
    }

    let mut l: u16 = g;
    let mut h: u16 = 0u16;

    for i in (2u16..8).step_by(2){
        g = 0;
        let tmp3: u16 = ((a as u16) >> i) & 3;
        for j in 0..4{
            let tmp2: u16 = tmp3.wrapping_sub(j as u16);
            g ^= u[j as usize] & (((tmp2 as u32 | (tmp2 as u32).wrapping_neg()) >> 31) as u16).wrapping_neg();
        }

        l ^= g << i;
        h ^= g >> (8 - i);
    }

    let mask: u16 = (((b as u16) >> 7) & 1).wrapping_neg();
    l ^= ((a as u16) << 7) & mask;
    h ^= ((a as u16) >> 1) & mask;

    c[0] = l as u8;
    c[1] = h as u8;
}

pub fn gf_mul(a: u16, b: u16) -> u16{
    let mut c = [0u8;2];
    gf_caryless_mul(&mut c, a as u8, b as u8);
    let tmp = (c[0] as u16) ^ (c[1] as u16) << 8;
    gf_reduce(tmp)
}

pub fn gf_square(a: u16) -> u16{
    let mut b: u32 = a as u32;
    let mut s: u32 = b as u32 & 1;
for i in 1..PARAM_M{
        b <<=1;
        s ^= b & (1 << (2 * i));
    }

    gf_reduce(s as u16)
}

pub fn gf_inverse(a: u16) -> u16{
    let mut inv: u16 = gf_square(a);
    let mut tmp1 = gf_mul(inv, a);
    inv = gf_square(inv);
    let tmp2 = gf_mul(inv, tmp1);
    tmp1 = gf_mul(inv, tmp2);
    inv = gf_mul(tmp1, inv);
    inv = gf_square(inv);
    inv = gf_square(inv);
    inv = gf_square(inv);
    inv = gf_mul(inv, tmp2);
    inv = gf_square(inv);

    inv
}


#[cfg(test)]
mod tests {
    use super::*;

    fn ref_reduce(mut x: u16) -> u8 {
        let poly: u16 = 0x11D;
        for bit in (8u32..=15).rev() {
            if x & (1u16 << bit) != 0 {
                x ^= poly << (bit - 8);
            }
        }
        x as u8
    }

    #[test]
    fn test_gf_reduce() {
        for i in 0u32..(1 << 16) {
            let expected = ref_reduce(i as u16);
            let actual = gf_reduce(i as u16) as u8;
            assert_eq!(actual, expected, "Failed for input {}", i);
        }
    }
}
