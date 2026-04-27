use crate::parameters::*;
use crate::symmetric;
use crate::vector;
use crate::gf2x;
use zeroize::Zeroize;
use crate::parsing;
use crate::data_structures;
use crate::code;
//use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use sha3::digest::ExtendableOutput;
use rand::RngExt;


pub(crate) fn hqc_pke_keygen(ek_pke: &mut [u8], dk_pke: &mut [u8], seed: &[u8]){
    let mut keypair_seed = [0u8; 2*SEED_BYTES];

    let mut x = [0u64; VEC_N_SIZE_64];
    let mut y = [0u64; VEC_N_SIZE_64];
    let mut h = [0u64; VEC_N_SIZE_64];
    let mut s = [0u64; VEC_N_SIZE_64];

    symmetric::hash_i(&mut keypair_seed, seed);

    let seed_dk = &keypair_seed[..SEED_BYTES];
    let seed_ek = &keypair_seed[SEED_BYTES..];


    let dk_xof_ctx = symmetric::xof_init(seed_dk);
    let ek_xof_ctx = symmetric::xof_init(seed_ek);
    let mut dk_reader = dk_xof_ctx.finalize_xof();
    vector::vect_sample_fixed_weight1(&mut dk_reader, &mut y, PARAM_OMEGA);
    vector::vect_sample_fixed_weight1(&mut dk_reader, &mut x, PARAM_OMEGA);
    let mut ek_reader = ek_xof_ctx.finalize_xof();

    //calcule la clé publique
    vector::vect_set_random(&mut ek_reader, &mut h);
    gf2x::vect_mul(&mut s, &y, &h);
    let s_copy = s.clone();
    vector::vect_add(&mut s, &x, &s_copy, VEC_N_SIZE_64);
    
    ek_pke[..SEED_BYTES].copy_from_slice(seed_ek);
    let s_bytes = unsafe {
        std::slice::from_raw_parts(s.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
    };
    ek_pke[SEED_BYTES..SEED_BYTES + VEC_N_SIZE_BYTES].copy_from_slice(s_bytes);
    dk_pke[..SEED_BYTES].copy_from_slice(seed_dk);

    keypair_seed.zeroize();
    x.zeroize();
    y.zeroize();
    drop(dk_reader);
    drop(ek_reader);
}

pub(crate) fn hqc_pke_encrypt(c_pke: &mut data_structures::CiphertextPke, ek_pke: &[u8], m: &[u64], theta: &[u8]){
    let mut h = [0u64;VEC_N_SIZE_64];
    let mut s = [0u64;VEC_N_SIZE_64];
    let mut r1 = [0u64;VEC_N_SIZE_64];
    let mut r2 = [0u64;VEC_N_SIZE_64];
    let mut e = [0u64;VEC_N_SIZE_64];
    let mut tmp = [0u64;VEC_N_SIZE_64];

    let theta_xof_ctx = symmetric::xof_init(theta);
    let mut theta_reader = theta_xof_ctx.finalize_xof();

    parsing::hqc_ek_pke_from_string(&mut h, &mut s, ek_pke);
    vector::vect_sample_fixed_weight2(&mut theta_reader, &mut r1, PARAM_OMEGA_R);
    vector::vect_sample_fixed_weight2(&mut theta_reader, &mut e, PARAM_OMEGA_E);
    vector::vect_sample_fixed_weight2(&mut theta_reader, &mut r2, PARAM_OMEGA_R);

    // u = r2·h + r1
    let mut u_tmp = [0u64; VEC_N_SIZE_64];
    gf2x::vect_mul(&mut u_tmp, &r2, &h);
    vector::vect_add(&mut c_pke.u, &r1, &u_tmp, VEC_N_SIZE_64);

    // v = encode(m) + truncate(r2·s + e)
    let mut v_encoded = [0u64; VEC_N1N2_SIZE_64];
    code::code_encode(&mut v_encoded, m);
    gf2x::vect_mul(&mut tmp, &r2, &s);
    let tmp_copy = tmp.clone();
    vector::vect_add(&mut tmp, &e, &tmp_copy, VEC_N_SIZE_64);
    vector::vect_truncate(&mut tmp);
    vector::vect_add(&mut c_pke.v, &v_encoded, &tmp, VEC_N1N2_SIZE_64);

    r1.zeroize();
    r2.zeroize();
    e.zeroize();
    tmp.zeroize();
    drop(theta_reader);
}

pub(crate) fn hqc_pke_decrypt(m: &mut [u64], dk_pke: &[u8], c_pke: &data_structures::CiphertextPke){
    let mut y= [0u64; VEC_N_SIZE_64];
    let mut tmp1= [0u64; VEC_N_SIZE_64];
    let mut tmp2= [0u64; VEC_N1N2_SIZE_64];

    parsing::hqc_dk_pke_from_string(&mut y, dk_pke);

    gf2x::vect_mul(&mut tmp1, &y, &c_pke.u);
    vector::vect_truncate(&mut tmp1);
    vector::vect_add(&mut tmp2, &c_pke.v, &tmp1, VEC_N1N2_SIZE_64);

    code::code_decode(m, &tmp2);

    y.zeroize();
    tmp1.zeroize();
    tmp2.zeroize();

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::CiphertextPke;

    #[test]
    fn test_pke_api() {
        let mut rng = rand::rng();
        let mut seed = [0u8; SEED_BYTES];
        let mut theta = [0u8; SEED_BYTES];
        let mut m1 = [0u64; VEC_K_SIZE_64];
        let mut m2 = [0u64; VEC_K_SIZE_64];

        rng.fill(&mut seed);
        rng.fill(&mut theta);

        let m1_bytes = unsafe {
            std::slice::from_raw_parts_mut(m1.as_mut_ptr() as *mut u8, PARAM_K)
        };
        rng.fill(m1_bytes);

        let mut ek_pke = [0u8; PUBLIC_KEY_BYTES];
        let mut dk_pke = [0u8; SECRET_KEY_BYTES];
        let mut c_pke = CiphertextPke {
            u: [0u64; VEC_N_SIZE_64],
            v: [0u64; VEC_N1N2_SIZE_64],
        };

        hqc_pke_keygen(&mut ek_pke, &mut dk_pke, &seed);
        hqc_pke_encrypt(&mut c_pke, &ek_pke, &m1, &theta);
        hqc_pke_decrypt(&mut m2, &dk_pke, &c_pke);

        assert_eq!(m1, m2, "Message décrypté différent du message original !");
    }

    #[test]
    fn test_pke_zero_message() {
        let seed = [0u8; SEED_BYTES];
        let theta = [0u8; SEED_BYTES];
        let m1 = [0u64; VEC_K_SIZE_64];
        let mut m2 = [0u64; VEC_K_SIZE_64];

        let mut ek_pke = [0u8; PUBLIC_KEY_BYTES];
        let mut dk_pke = [0u8; SECRET_KEY_BYTES];
        let mut c_pke = CiphertextPke {
            u: [0u64; VEC_N_SIZE_64],
            v: [0u64; VEC_N1N2_SIZE_64],
        };

        hqc_pke_keygen(&mut ek_pke, &mut dk_pke, &seed);
        hqc_pke_encrypt(&mut c_pke, &ek_pke, &m1, &theta);
        hqc_pke_decrypt(&mut m2, &dk_pke, &c_pke);

        assert_eq!(m1, m2, "PKE échoue avec message nul !");
    }

    #[test]
    fn test_code_encode_decode() {
        let mut rng = rand::rng();
        let mut m1 = [0u64; VEC_K_SIZE_64];
        let m1_bytes = unsafe {
            std::slice::from_raw_parts_mut(m1.as_mut_ptr() as *mut u8, PARAM_K)
        };
        rng.fill(m1_bytes);

        let mut em = [0u64; VEC_N1N2_SIZE_64];
        code::code_encode(&mut em, &m1);

        let mut m2 = [0u64; VEC_K_SIZE_64];
        code::code_decode(&mut m2, &em);

        assert_eq!(m1, m2, "code_encode/decode échoue !");
    }

    #[test]
    fn test_ring_property() {
        let mut a = [0u64; VEC_N_SIZE_64];
        let mut b = [0u64; VEC_N_SIZE_64];
        a[0] = 2; // X^1
        b[(PARAM_N - 1) / 64] = 1u64 << ((PARAM_N - 1) % 64); // X^(N-1)
        let mut result = [0u64; VEC_N_SIZE_64];
        gf2x::vect_mul(&mut result, &a, &b);
        assert_eq!(result[0], 1, "X * X^(N-1) != 1 dans l'anneau !");
    }
}
