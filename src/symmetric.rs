use crate::parameters::*;
use crate::data_structures::*;
use sha3::digest::core_api::CoreWrapper;
use sha3::{Digest, Sha3_256, Sha3_512, Shake256, digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};

pub const HQC_XOF_DOMAIN: u8 = 1;
pub const HQC_G_FCT_DOMAIN: u8 = 0;
pub const HQC_H_FCT_DOMAIN: u8 = 1;
pub const HQC_I_FCT_DOMAIN: u8 = 2;
pub const HQC_J_FCT_DOMAIN: u8 = 3;
pub const HQC_PRNG_DOMAIN: u8 = 0;

pub fn prng_init(entropy_input: &[u8], personalization_string: &[u8]) -> sha3::digest::core_api::XofReaderCoreWrapper<sha3::Shake256ReaderCore>{
    let domain = HQC_PRNG_DOMAIN;
    let mut shake256_prng_ctx = Shake256::default();
    Update::update(&mut shake256_prng_ctx, entropy_input);
    Update::update(&mut shake256_prng_ctx, personalization_string);
    Update::update(&mut shake256_prng_ctx, &[domain]);

    shake256_prng_ctx.finalize_xof()
}

pub fn prng_get_bytes(ctx: &mut impl XofReader, output: &mut [u8]){
    ctx.read(output);
}

pub fn xof_init(seed: &[u8]) -> sha3::Shake256 {
    let xof_domain: u8 = HQC_XOF_DOMAIN;
    
    let mut xof_ctx = Shake256::default();
    Update::update(&mut xof_ctx, seed);
    Update::update(&mut xof_ctx, &[xof_domain]);
    
    xof_ctx
}

pub fn xof_get_bytes(xof_ctx: &mut impl XofReader, output: &mut [u8]){
    xof_ctx.read(output);
}
pub fn hash_i(output: &mut [u8], seed: &[u8]) {
    let mut ctx = Sha3_512::new();
    Digest::update(&mut ctx, seed);
    Digest::update(&mut ctx, &[HQC_I_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
}

pub fn hash_h(output: &mut [u8], ek_kem: &[u8; PUBLIC_KEY_BYTES]){
    let mut ctx = Sha3_256::new();
    Digest::update(&mut ctx, ek_kem);
    Digest::update(&mut ctx, &[HQC_H_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
} 

pub fn hash_g(output: &mut [u8], hash_ek_kem: &[u8; SEED_BYTES], m: &[u8; PARAM_SECURITY_BYTES], salt: &[u8; SALT_BYTES]){
    let mut ctx = Sha3_512::new();
    Digest::update(&mut ctx, hash_ek_kem); 
    Digest::update(&mut ctx, m);
    Digest::update(&mut ctx, salt);
    Digest::update(&mut ctx, &[HQC_G_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
}

pub fn hash_j(output: &mut [u8], hash_ek_kem: &[u8; SEED_BYTES], sigma: &[u8; PARAM_SECURITY_BYTES], c_kem: &CiphertextKem){
    let mut ctx = Sha3_256::new();
    let u_bytes = unsafe {
        std::slice::from_raw_parts(c_kem.c_pke.u.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
    };
    let v_bytes = unsafe {
        std::slice::from_raw_parts(c_kem.c_pke.v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES)
    };

    Digest::update(&mut ctx, hash_ek_kem);
    Digest::update(&mut ctx, sigma);


    Digest::update(&mut ctx, u_bytes);
    Digest::update(&mut ctx, v_bytes);
    Digest::update(&mut ctx, &c_kem.salt);
    Digest::update(&mut ctx, &[HQC_J_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());

}

