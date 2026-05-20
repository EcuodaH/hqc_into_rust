use crate::symmetric;
use crate::hqc;
use sha3::digest::core_api::CoreWrapper;
use sha3::{Digest, Sha3_256, Sha3_512, Shake256, digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use crate::parameters::*;
use zeroize::Zeroize;
use crate::vector;
use crate::parsing;
use crate::data_structures;


pub fn crypto_kem_keypair(ek_kem: &mut [u8], dk_kem: &mut [u8], ctx: &mut impl XofReader){
    let mut seed_kem = [0u8; SEED_BYTES];
    let mut sigma = [0u8; PARAM_SECURITY_BYTES];
    let mut seed_pke = [0u8; SEED_BYTES];

    let mut ek_pke = [0u8; PUBLIC_KEY_BYTES];
    let mut dk_pke= [0u8;SEED_BYTES];

    symmetric::prng_get_bytes(ctx, &mut seed_kem);

    let ctx_kem = symmetric::xof_init(&seed_kem);
    let mut kem_reader = ctx_kem.finalize_xof();
    symmetric::xof_get_bytes(&mut kem_reader, &mut seed_pke);
    symmetric::xof_get_bytes(&mut kem_reader, &mut sigma);


    hqc::hqc_pke_keygen(&mut ek_pke,&mut dk_pke, &seed_pke);  


    ek_kem[0..PUBLIC_KEY_BYTES].copy_from_slice(&ek_pke[..PUBLIC_KEY_BYTES]);

    dk_kem[0..PUBLIC_KEY_BYTES].copy_from_slice(&ek_pke[..PUBLIC_KEY_BYTES]);
    dk_kem[(PUBLIC_KEY_BYTES)..(PUBLIC_KEY_BYTES+SEED_BYTES)].copy_from_slice(&dk_pke[..SEED_BYTES]);
    dk_kem[(PUBLIC_KEY_BYTES+SEED_BYTES)..(PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES)].copy_from_slice(&sigma[..PARAM_SECURITY_BYTES]);
    dk_kem[(PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES)..(PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES+SEED_BYTES)].copy_from_slice(&seed_kem[..SEED_BYTES]);

    seed_kem.zeroize();
    sigma.zeroize();
    seed_pke.zeroize();
    dk_pke.zeroize();
}

pub fn crypto_kem_enc(c_kem : &mut [u8], k : &mut [u8], ek_kem : &[u8], ctx: &mut impl XofReader){
    let mut m = [0u8; PARAM_SECURITY_BYTES];
    let mut k_theta = [0u8; SHARED_SECRET_BYTES + SEED_BYTES];
    let mut theta = [0u8; SEED_BYTES];
    let mut hash_ek_kem = [0u8; SEED_BYTES];
    let mut c_kem_t = data_structures::CiphertextKem {
        c_pke: data_structures::CiphertextPke { 
            u: [0u64; VEC_N_SIZE_64], 
            v: [0u64; VEC_N1N2_SIZE_64], 
        },
        salt: [0u8; SALT_BYTES],
    };
    
    symmetric::prng_get_bytes(ctx, &mut m);
    symmetric::prng_get_bytes(ctx, &mut c_kem_t.salt);



    let ek_kem_array = ek_kem.try_into().unwrap();
    symmetric::hash_h(&mut hash_ek_kem, ek_kem_array);

    symmetric::hash_g(&mut k_theta, &hash_ek_kem, &m, &c_kem_t.salt);
    theta[0..SEED_BYTES].copy_from_slice(&k_theta[SHARED_SECRET_BYTES..SHARED_SECRET_BYTES+SEED_BYTES]);

    let m_array = unsafe{
        std::slice::from_raw_parts(m.as_ptr() as *const u64, PARAM_SECURITY_BYTES/8)
    };
    hqc::hqc_pke_encrypt(&mut c_kem_t.c_pke, ek_kem, &m_array, &theta);

    parsing::hqc_c_kem_to_string(c_kem, &c_kem_t);
    k[0..SHARED_SECRET_BYTES].copy_from_slice(&k_theta[..SHARED_SECRET_BYTES]);

    m.zeroize();
    k_theta.zeroize();
    theta.zeroize();
}


pub fn crypto_kem_dec(k_prime: &mut [u8], c_kem : &[u8], dk_kem: &[u8]){
    let mut ek_pke = [0u8; PUBLIC_KEY_BYTES];
    let mut dk_pke = [0u8; SEED_BYTES];
    let mut sigma = [0u8; PARAM_SECURITY_BYTES];
    let mut m_prime = [0u8; PARAM_SECURITY_BYTES];
    let mut hash_ek_kem = [0u8; SEED_BYTES];
    let mut k_theta_prime = [0u8; SHARED_SECRET_BYTES + SEED_BYTES];
    let mut k_bar = [0u8; SHARED_SECRET_BYTES];
    let mut theta_prime = [0u8; SEED_BYTES];

    let mut c_kem_t = data_structures::CiphertextKem {
        c_pke: data_structures::CiphertextPke { 
            u: [0u64; VEC_N_SIZE_64], 
            v: [0u64; VEC_N1N2_SIZE_64], 
        },
        salt: [0u8; SALT_BYTES],
    };

    let mut c_kem_prime_t = data_structures::CiphertextKem {
        c_pke: data_structures::CiphertextPke { 
            u: [0u64; VEC_N_SIZE_64], 
            v: [0u64; VEC_N1N2_SIZE_64], 
        },
        salt: [0u8; SALT_BYTES],
    };

    ek_pke[..PUBLIC_KEY_BYTES].copy_from_slice(&dk_kem[..PUBLIC_KEY_BYTES]);
    dk_pke[..SEED_BYTES].copy_from_slice(&dk_kem[PUBLIC_KEY_BYTES..PUBLIC_KEY_BYTES+SEED_BYTES]);
    sigma[..PARAM_SECURITY_BYTES].copy_from_slice(&dk_kem[PUBLIC_KEY_BYTES+SEED_BYTES..PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES]);

    parsing::hqc_c_kem_from_string(&mut c_kem_t.c_pke, &mut c_kem_t.salt, &c_kem);


    let mut m_prime_array = unsafe{
        std::slice::from_raw_parts_mut(m_prime.as_ptr() as *mut u64, PARAM_SECURITY_BYTES/8)
    };
    hqc::hqc_pke_decrypt(&mut m_prime_array, &dk_pke, &c_kem_t.c_pke);

    symmetric::hash_h(&mut hash_ek_kem, &ek_pke);
    symmetric::hash_g(&mut k_theta_prime, &hash_ek_kem, &m_prime, &c_kem_t.salt);
    k_prime[..SHARED_SECRET_BYTES].copy_from_slice(&k_theta_prime[..SHARED_SECRET_BYTES]);
    theta_prime[..SEED_BYTES].copy_from_slice(&k_theta_prime[SHARED_SECRET_BYTES..SHARED_SECRET_BYTES+SEED_BYTES]);

    hqc::hqc_pke_encrypt(&mut c_kem_prime_t.c_pke, &ek_pke, &m_prime_array, &theta_prime);
    c_kem_prime_t.salt[..SALT_BYTES].copy_from_slice(&c_kem_t.salt);

    symmetric::hash_j(&mut k_bar, &hash_ek_kem, &sigma, &c_kem_t);

    let mut result = 0u8;

    let c_kem_t_u_bytes = unsafe {
        std::slice::from_raw_parts(c_kem_t.c_pke.u.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
    };
    let c_kem_t_v_bytes = unsafe {
        std::slice::from_raw_parts(c_kem_t.c_pke.v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES)
    };

    let c_kem_prime_t_u_bytes = unsafe {
        std::slice::from_raw_parts(c_kem_prime_t.c_pke.u.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
    };
    let c_kem_prime_t_v_bytes = unsafe {
        std::slice::from_raw_parts(c_kem_prime_t.c_pke.v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES)
    };

    result |= vector::vect_compare(c_kem_t_u_bytes, c_kem_prime_t_u_bytes, VEC_N_SIZE_BYTES);
    result |= vector::vect_compare(c_kem_t_v_bytes, c_kem_prime_t_v_bytes, VEC_N1N2_SIZE_BYTES);
    result |= vector::vect_compare(&c_kem_t.salt, &c_kem_prime_t.salt, SALT_BYTES);
    result = result.wrapping_sub(1);

    for i in 0..SHARED_SECRET_BYTES{
        k_prime[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
    }

    dk_pke.zeroize();
    sigma.zeroize();
    m_prime.zeroize();
    k_theta_prime.zeroize();
    k_bar.zeroize();
    theta_prime.zeroize();
}