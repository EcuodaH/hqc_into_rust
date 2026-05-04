use crate::symmetric;
use crate::hqc;
use sha3::digest::core_api::CoreWrapper;
use sha3::{Digest, Sha3_256, Sha3_512, Shake256, digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use crate::parameters::*;
use zeroize::Zeroize;
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
    dk_kem[0..PUBLIC_KEY_BYTES].copy_from_slice(&ek_kem[..PUBLIC_KEY_BYTES]);
    dk_kem[(PUBLIC_KEY_BYTES)..(PUBLIC_KEY_BYTES+SEED_BYTES)].copy_from_slice(&dk_pke[..SEED_BYTES]);
    dk_kem[(PUBLIC_KEY_BYTES+SEED_BYTES)..(PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES)].copy_from_slice(&sigma[..PARAM_SECURITY_BYTES]);
    dk_kem[(PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES)..(PUBLIC_KEY_BYTES+SEED_BYTES+PARAM_SECURITY_BYTES+SEED_BYTES)].copy_from_slice(&seed_kem[..SEED_BYTES]);

    seed_kem.zeroize();
    sigma.zeroize();
    seed_pke.zeroize();
    dk_pke.zeroize();
}

pub fn crypto_kem_enc(c_kem : &mut [u8], K : &mut [u8], ek_kem : &[u8], ctx: &mut impl XofReader){
    let mut m = [0u8; PARAM_SECURITY_BYTES];
    let mut c_kem_t = data_structures::CiphertextKem {
        c_pke: data_structures::CiphertextPke { 
            u: [0u64; VEC_N_SIZE_64], 
            v: [0u64; VEC_N1N2_SIZE_64], 
        },
        salt: [0u8; SALT_BYTES],
    };
    
    symmetric::prng_get_bytes(ctx, &mut m);
    symmetric::prng_get_bytes(ctx, &mut c_kem_t.salt);
}