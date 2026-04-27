
use crate::parameters::*;
use sha3::digest::XofReader;

fn compare_u32(v1: u32, v2: u32) -> u32{
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}


//calcul de (x % PARAM_N) de manière optimisée
fn barrett_reduce(x: u32) -> u32{
    let q: u64 = ((x as u64) * PARAM_N_MU) >> 32; 
    let r: u32 = x.wrapping_sub((q * (PARAM_N as u64)) as u32);

    let reduce_flag = (r.wrapping_sub(PARAM_N as u32) >> 31) ^ 1;
    let mask = reduce_flag.wrapping_neg();
    r.wrapping_sub(mask & (PARAM_N as u32))
}

//crée les indices à modifier pour créer ensuite un vecteur epars avec vect_write_support_to_vector
pub fn vect_generate_random_support1(ctx: &mut impl XofReader, support: &mut [u32], weight: usize) {
    let mut rand_bytes = [0u8; 3];

    let mut i = 0;
    while i < weight {
        ctx.read(&mut rand_bytes);
        let mut candidate = rand_bytes[0] as u32 
        | (rand_bytes[1] as u32) << 8 
        | (rand_bytes[2] as u32) << 16;

        if candidate >= UTILS_REJECTION_THRESHOLD {
            continue;
        }

        candidate = barrett_reduce(candidate);

        let mut is_position_available = 1;
        for j in 0..i{
            if candidate == support[j]{
                is_position_available = 0;
                break;
            }
        }
        
    if is_position_available == 1 {
            support[i] = candidate;
            i+=1;
        }
    }
}

pub fn vect_generate_random_support2(ctx: &mut impl XofReader, support: &mut [u32], weight: usize){
    let mut rand_u32 = [0u32; PARAM_OMEGA_R];
    let rand_bytes = unsafe {
        std::slice::from_raw_parts_mut(rand_u32.as_mut_ptr() as *mut u8, 4 * weight)
    };
    ctx.read(rand_bytes);

    for i in 0..weight {
        let buf: u64 = rand_u32[i] as u64;
        support[i] = (i as u64 + ((buf * ((PARAM_N - i) as u64)) >> 32)) as u32;
    }

    for i in (0..(weight-1)).rev(){
        let mut found = 0u32;
        for j in i+1..weight {
            found |= compare_u32(support[i], support[j]);
        }

        let mask = found.wrapping_neg();
        support[i] = (mask & i as u32) ^(!mask & support[i]);
    }

}

//crée le vecteur epars réellement le vecteur épars
pub fn vect_write_support_to_vector(v: &mut [u64], support: &mut [u32], weight:usize){
    let mut index_tab = [0u32; PARAM_OMEGA_R];
    let mut bit_tab = [0u64; PARAM_OMEGA_R];

        for i in 0..weight {
            index_tab[i] = support[i] >> 6;
            let pos: u32 = (support[i] & 0x3f) as u32;
            bit_tab[i] = 1u64 << pos;
        }

        for i in 0..VEC_N_SIZE_64 {
            let mut val: u64 = 0;
            for j in 0..weight {
                let tmp: u32 = (i as u32).wrapping_sub(index_tab[j]);
                let val1: u32 = 1 ^ ((tmp | tmp.wrapping_neg()) >> 31);
                let mask: u64 = (val1 as u64).wrapping_neg();
                val |= bit_tab[j] & mask ;
            }
            v[i] |= val;
        }
}

// fonction à appeler pour créer le vecteur épars
pub fn vect_sample_fixed_weight1(ctx: &mut impl XofReader, v: &mut [u64], weight: usize) {
    let mut support = [0u32; PARAM_OMEGA_R];
    vect_generate_random_support1(ctx, &mut support, weight);
    vect_write_support_to_vector(v, &mut support, weight);

}

pub fn vect_sample_fixed_weight2(ctx: &mut impl XofReader, v: &mut [u64], weight: usize) {
    let mut support = [0u32; PARAM_OMEGA_R];
    vect_generate_random_support2(ctx, &mut support, weight);
    vect_write_support_to_vector(v, &mut support, weight);

}

//
pub fn vect_set_random(ctx: &mut impl XofReader, v: &mut [u64]) {
    let v_bytes = unsafe {
        std::slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, VEC_N_SIZE_BYTES)
    };
    ctx.read(v_bytes);
    
    v[VEC_N_SIZE_64 - 1] &= bitmask(PARAM_N, 64);
}

pub fn vect_add(o: &mut [u64], v1: &[u64], v2: &[u64], size: usize){
    for i in 0..size{
        o[i] = v1[i] ^ v2[i];
    }
}

pub fn vect_truncate(v: &mut [u64]){
    let orig_words: usize = (PARAM_N + 63) /64;
    let mut new_full_words: usize = PARAM_N1N2 / 64;
    let remaining_bits: usize = PARAM_N1N2 % 64;

    if remaining_bits > 0 {
        let mask = (1u64 << remaining_bits) -1;
        v[new_full_words] &= mask;
        new_full_words += 1;
    }

    for i in new_full_words..orig_words{
        v[i] = 0;
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrett_reduce() {
        // Test exhaustif sur une grande plage
        for x in 0u32..(1 << 24) {
            let expected = x % PARAM_N as u32;
            let actual = barrett_reduce(x);
            assert_eq!(actual, expected, "Failed for input {}", x);
        }

        // Valeurs limites
        let edge_vals = [0u32, 1, PARAM_N as u32 - 1, PARAM_N as u32, PARAM_N as u32 + 1, u32::MAX];
        for x in edge_vals {
            let expected = x % PARAM_N as u32;
            let actual = barrett_reduce(x);
            assert_eq!(actual, expected, "Failed for edge value {}", x);
        }
    }
}

#[test]
fn test_vect_fixed_weight1() {
    use sha3::digest::ExtendableOutput;
    use crate::symmetric;
    
    let mut v = [0u64; VEC_N_SIZE_64];
    let seed = [0u8; SEED_BYTES];
    
    let ctx = symmetric::xof_init(&seed);
    let mut reader = ctx.finalize_xof();
    
    let mut support = [0u32; PARAM_OMEGA];
    vect_generate_random_support1(&mut reader, &mut support, PARAM_OMEGA);
    
    let mut unique = true;
    for i in 0..PARAM_OMEGA {
        for j in 0..i {
            if support[i] == support[j] {
                unique = false;
            }
        }
    }
    assert!(unique, "Support has duplicates!");
    
    vect_write_support_to_vector(&mut v, &mut support, PARAM_OMEGA);
    let weight: u32 = v.iter().map(|w| w.count_ones()).sum();
    assert_eq!(weight, PARAM_OMEGA as u32);
}

#[test]
fn test_vect_fixed_weight2() {
    use sha3::digest::ExtendableOutput;
    use crate::symmetric;
    
    let mut v = [0u64; VEC_N_SIZE_64];
    let seed = [0u8; SEED_BYTES];
    
    let ctx = symmetric::xof_init(&seed);
    let mut reader = ctx.finalize_xof();
    
    vect_sample_fixed_weight2(&mut reader, &mut v, PARAM_OMEGA_R);
    
    let weight: u32 = v.iter().map(|w| w.count_ones()).sum();
    assert_eq!(weight, PARAM_OMEGA_R as u32, "Mauvais poids de Hamming");
}

#[test]
fn test_vect_truncate() {
    use rand::Rng;
    
    let mut v = [0u64; VEC_N_SIZE_64];
    // Remplir avec des valeurs aléatoires
    for word in v.iter_mut() {
        *word = rand::random();
    }
    let copy = v.clone();
    
    vect_truncate(&mut v);
    
    let full_words = PARAM_N1N2 / 64;
    let rem_bits = PARAM_N1N2 % 64;
    
    // Les mots complets avant la troncature sont inchangés
    for i in 0..full_words {
        assert_eq!(v[i], copy[i]);
    }
    
    // Le mot partiel est masqué
    if rem_bits > 0 {
        let mask = (1u64 << rem_bits) - 1;
        assert_eq!(v[full_words], copy[full_words] & mask);
    }
    
    // Les mots suivants sont à zéro
    let first_zero = if rem_bits > 0 { full_words + 1 } else { full_words };
    for i in first_zero..VEC_N_SIZE_64 {
        assert_eq!(v[i], 0);
    }
}