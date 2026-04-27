use std::error;

use zeroize::Zeroize;
use rand::RngExt;


use crate::parameters::*;
use crate::tables::*;

use crate::fft;
use crate::gf;


const RS_POLY_COEFS: [u16; PARAM_G] = [
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21,
    139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1
];

pub fn reed_solomon_encode(cdw: &mut [u64], msg: & [u64]){
    let mut tmp: [u16; 31] = [0u16; PARAM_G];

    let mut msg_bytes: [u8; 16] = [0u8; PARAM_K];
    let mut cdw_bytes: [u8; 46] = [0u8; PARAM_N1];

    let msg_bytes_src: &[u8] = unsafe {
        std::slice::from_raw_parts(msg.as_ptr() as *const u8, PARAM_K)
    };
    msg_bytes.copy_from_slice(msg_bytes_src);

    for i in 0..PARAM_K{
        let gate_value = msg_bytes[PARAM_K -1 -i] ^ cdw_bytes[PARAM_N1 - PARAM_K -1];

        for j in 0..PARAM_G{
            tmp[j] = gf::gf_mul(gate_value as u16, RS_POLY_COEFS[j]);
        }

        for k in (1..=(PARAM_N1 - PARAM_K - 1)).rev(){
            cdw_bytes[k] = cdw_bytes[k - 1] ^ (tmp[k] as u8);
        }
         cdw_bytes[0] = tmp[0] as u8;
    }
    cdw_bytes[PARAM_N1 - PARAM_K..].copy_from_slice(&msg_bytes);
    let cdw_raw = unsafe {
        std::slice::from_raw_parts_mut(cdw.as_mut_ptr() as *mut u8, PARAM_N1)
    };
    cdw_raw.copy_from_slice(&cdw_bytes);
}

fn mod_val(i: u16, modulus: u16) -> u16{
    let tmp = i.wrapping_sub(modulus);
    let mask = (-(( tmp >> 15) as i16)) as u16;

    tmp + (mask & modulus)
}

fn compute_syndromes(syndromes: &mut [u16], cdw: &[u8]){
    for i in 0..(2*PARAM_DELTA){
        for j in 1..PARAM_N1{
            syndromes[i] ^= gf::gf_mul(cdw[j] as u16, ALPHA_IJ_POW[i][j -1]);
        }
        syndromes[i] ^= cdw[0] as u16;
    }
}

fn compute_elp(sigma: &mut [u16], syndromes: &[u16]) -> u16{
    let mut deg_sigma = 0u16;
    let mut deg_sigma_p = 0u16;
    let mut sigma_copy = [0u16; PARAM_DELTA + 1];
    let mut x_sigma_p = [0u16; PARAM_DELTA + 1];
    x_sigma_p[1] = 1;
    let mut pp: u16 = u16::MAX;
    let mut d_p = 1u16;
    let mut d = syndromes[0];
    

    sigma[0] = 1;
    for mu in 0..(2*PARAM_DELTA){
        sigma_copy.copy_from_slice(&sigma[..PARAM_DELTA + 1]);
        let deg_sigma_copy = deg_sigma;
        let dd = gf::gf_mul(d, gf::gf_inverse(d_p));

        for i in 1..=((mu + 1).min(PARAM_DELTA)){
            sigma[i] ^= gf::gf_mul(dd, x_sigma_p[i]);
        }

        let deg_x = (mu as u16).wrapping_sub(pp);
        let deg_x_sigma_p = deg_x.wrapping_add(deg_sigma_p);

        let mask1 = (d.wrapping_neg() >> 15).wrapping_neg();
        let mask2 = (deg_sigma.wrapping_sub(deg_x_sigma_p) >> 15).wrapping_neg();


        let mask12__ = std::hint::black_box(mask1 & mask2);
        let mask12 = mask12__;
        deg_sigma ^= mask12 & (deg_x_sigma_p ^ deg_sigma);

        if mu == (2 * PARAM_DELTA - 1){
            break;
        }

        pp ^= mask12 & ((mu as u16) ^ pp);
        d_p ^= mask12 & (d ^ d_p);
        for i in (1..=PARAM_DELTA).rev(){
            x_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (!mask12 & x_sigma_p[i - 1]);
        }

        deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
        d = syndromes[mu + 1];

        for i in 1..=(mu +1).min(PARAM_DELTA){
            d ^= gf::gf_mul(sigma[i], syndromes[mu + 1 - i]);
        }
    }
    deg_sigma
}

fn compute_roots(error: &mut [u8], sigma: &[u16]){
    let mut w = [0u16; (1 << PARAM_M)];

    fft::fft(&mut w, sigma, PARAM_DELTA + 1);
    fft::fft_retrieve_error_poly(error, &w);
    
}

fn compute_z_poly(z: &mut [u16], sigma: &[u16], degree: u16, syndromes: &[u16]){
    z[0] = 1;

    for i in 1..(PARAM_DELTA + 1){
        let mask = ((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15).wrapping_neg();
        z[i] = mask & sigma[i];
    }

    z[1] ^= syndromes[0];

    for i in 2..=PARAM_DELTA{
        let mask = ((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15).wrapping_neg();
        z[i] ^= mask & syndromes[i - 1];
        for j in 1..i{
            z[i] ^= mask & gf::gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }
}

fn compute_error_values(error_values: &mut [u16], z: &[u16], error: &[u8]){
    let mut beta_j: [u16; 15] = [0u16; PARAM_DELTA];
    let mut e_j: [u16; 15] = [0u16; PARAM_DELTA];

    let mut delta_counter: u16 = 0u16;
    for  i in 0..PARAM_N1{
        let mut found: u16 = 0u16;
        let mask1: u16 = ((error[i] as i32).wrapping_neg()>> 31) as u16;
        for j in 0..PARAM_DELTA{
            let mask2: u16 = !((((j as i32) ^ (delta_counter as i32)).wrapping_neg() >> 31) as u16);
            beta_j[j] += mask1 & mask2 & GF_EXP[i];
            found += mask1 & mask2 & 1;
        }
        delta_counter += found;
    }
    let delta_real_value = delta_counter;

    for i in 0..PARAM_DELTA{
        let mut tmp1: u16 = 1u16;
        let mut tmp2: u16 = 1u16;
        let inverse: u16 = gf::gf_inverse(beta_j[i]);
        let mut inverse_power_j: u16 = 1u16;

        for j in 1..=PARAM_DELTA{
            inverse_power_j = gf::gf_mul(inverse_power_j, inverse);
            tmp1 ^= gf::gf_mul(inverse_power_j, z[j]);
        }

        for k in 1..PARAM_DELTA{
            tmp2 = gf::gf_mul(tmp2, 1 ^ gf::gf_mul(inverse, beta_j[(i+k) % PARAM_DELTA]) );
        }

        let mask1: u16 = ((i as i16).wrapping_sub(delta_real_value as i16) >> 15) as u16;
        e_j[i] = mask1 & gf::gf_mul(tmp1, gf::gf_inverse(tmp2));
    }

    delta_counter = 0;
    for i in 0..PARAM_N1{
        let mut found: u16 = 0u16;
        let mask1: u16 = (((error[i] as i32).wrapping_neg()) >> 31) as u16;
        for j in 0..PARAM_DELTA{
            let mask2: u16 = !((((j as i32) ^ (delta_counter as i32)).wrapping_neg() >> 31) as u16);
            error_values[i] += mask1 & mask2 & e_j[j];
            found += mask1 & mask2 & 1;
        }
        delta_counter += found
    }
}

fn correct_errors(cdw:&mut [u8], error_values: &[u16]){
    for i in 0..PARAM_N1{
        cdw[i] ^= error_values[i] as u8;
    }
}

pub fn reed_solomon_decode(msg : &mut [u64], cdw: &mut [u64]){
    let mut cdw_bytes = [0u8; PARAM_N1];
    let mut syndromes = [0u16; 2 * PARAM_DELTA];
    let mut sigma = [0u16; 1 << PARAM_FFT];
    let mut error = [0u8; 1 << PARAM_M];
    let mut z = [0u16; PARAM_N1];
    let mut error_values = [0u16; PARAM_N1];
    
    let cdw_src = unsafe {
        std::slice::from_raw_parts(cdw.as_ptr() as *const u8, PARAM_N1)
    };
    cdw_bytes.copy_from_slice(cdw_src);

    compute_syndromes(&mut syndromes, &cdw_bytes);
    
    let deg = compute_elp(&mut sigma, &syndromes);

    compute_roots(&mut error, &sigma);

    compute_z_poly(&mut z, &sigma, deg, &syndromes);

    compute_error_values(&mut error_values, &z, &error);

    correct_errors(&mut cdw_bytes, &error_values);

    let msg_dst = unsafe {
        std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, PARAM_K)
    };
    msg_dst.copy_from_slice(&cdw_bytes[PARAM_G - 1..PARAM_G - 1 + PARAM_K]);

    cdw_bytes.zeroize();
}

#[test]
fn test_reed_solomon_encode_decode() {
    let mut rng = rand::rng();
    let mut msg = [0u64; VEC_K_SIZE_64];
    let msg_bytes = unsafe {
        std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, PARAM_K)
    };
    rng.fill(msg_bytes);
    
    let mut cw = [0u64; VEC_N1_SIZE_64];
    reed_solomon_encode(&mut cw, &msg);
    
    let mut decoded = [0u64; VEC_K_SIZE_64];
    let mut cw_copy = cw.clone();
    reed_solomon_decode(&mut decoded, &mut cw_copy);
    
    assert_eq!(msg, decoded, "Encode/decode sans erreur échoue !");
}

#[test]
fn test_reed_solomon_one_error() {
    let mut rng = rand::rng();
    
    for pos in 0..PARAM_N1 {
        let mut msg = [0u64; VEC_K_SIZE_64];
        let msg_bytes = unsafe {
            std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, PARAM_K)
        };
        rng.fill(msg_bytes);
        
        let mut cw = [0u64; VEC_N1_SIZE_64];
        reed_solomon_encode(&mut cw, &msg);
        
        // Injecter une erreur à la position pos
        let cw_bytes = unsafe {
            std::slice::from_raw_parts_mut(cw.as_mut_ptr() as *mut u8, PARAM_N1)
        };
        cw_bytes[pos] ^= 0xFF;
        
        let mut decoded = [0u64; VEC_K_SIZE_64];
        reed_solomon_decode(&mut decoded, &mut cw);
        
        assert_eq!(msg, decoded, "Failed at position {}", pos);
    }
}

#[test]
fn test_syndromes() {
    let mut rng = rand::rng();
    let mut msg = [0u64; VEC_K_SIZE_64];
    let msg_bytes = unsafe {
        std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, PARAM_K)
    };
    rng.fill(msg_bytes);
    
    let mut cw = [0u64; VEC_N1_SIZE_64];
    reed_solomon_encode(&mut cw, &msg);
    
    // Sans erreur — syndromes doivent être nuls
    let mut cw_bytes = [0u8; PARAM_N1];
    cw_bytes.copy_from_slice(unsafe {
        std::slice::from_raw_parts(cw.as_ptr() as *const u8, PARAM_N1)
    });
    let mut syndromes = [0u16; 2 * PARAM_DELTA];
    compute_syndromes(&mut syndromes, &cw_bytes);
    assert!(syndromes.iter().all(|&s| s == 0), "Syndromes non nuls sans erreur !");
    
    // Avec erreur à la position 11
    cw_bytes[11] ^= 0xFF;
    let mut syndromes2 = [0u16; 2 * PARAM_DELTA];
    compute_syndromes(&mut syndromes2, &cw_bytes);
    assert!(syndromes2.iter().any(|&s| s != 0), "Syndromes nuls avec erreur !");
}



#[test]
fn test_encode_zero() {
    let msg = [0u64; VEC_K_SIZE_64];
    let mut cw = [0u64; VEC_N1_SIZE_64];
    reed_solomon_encode(&mut cw, &msg);
    
    let cw_bytes = unsafe {
        std::slice::from_raw_parts(cw.as_ptr() as *const u8, PARAM_N1)
    };
    assert!(cw_bytes.iter().all(|&b| b == 0), "Message nul devrait donner codeword nul");
}

#[test]
fn test_reed_solomon_error_correction() {
    let mut rng = rand::rng();
    
    for _ in 0..100 {
        for nb_errors in 1..=PARAM_DELTA {
            let mut msg = [0u64; VEC_K_SIZE_64];
            let msg_bytes = unsafe {
                std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, PARAM_K)
            };
            rng.fill(msg_bytes);
            
            let mut cw = [0u64; VEC_N1_SIZE_64];
            reed_solomon_encode(&mut cw, &msg);
            
            let cw_bytes = unsafe {
                std::slice::from_raw_parts_mut(cw.as_mut_ptr() as *mut u8, PARAM_N1)
            };
            let mut positions = Vec::new();
            while positions.len() < nb_errors {
                let pos = rng.random_range(0..PARAM_N1);
                if !positions.contains(&pos) {
                    positions.push(pos);
                    cw_bytes[pos] ^= 0xFF;
                }
            }
            
            let mut decoded = [0u64; VEC_K_SIZE_64];
            reed_solomon_decode(&mut decoded, &mut cw);
            
            assert_eq!(msg, decoded, "Failed with {} errors", nb_errors);
        }
    }
}

