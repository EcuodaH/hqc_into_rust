use crate::parameters::*;
use sha3::{Sha3_256, Sha3_512, Shake256, Digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};

pub const HQC_XOF_DOMAIN: u8 = 1;
pub const HQC_G_FCT_DOMAIN: u8 = 0;
pub const HQC_H_FCT_DOMAIN: u8 = 1;
pub const HQC_I_FCT_DOMAIN: u8 = 2;
pub const HQC_J_FCT_DOMAIN: u8 = 3;

pub fn xof_init(seed: &[u8]) -> sha3::Shake256 {
    let xof_domain: u8 = HQC_XOF_DOMAIN;
    
    let mut xof_ctx = Shake256::default();
    Update::update(&mut xof_ctx, seed);
    Update::update(&mut xof_ctx, &[xof_domain]);
    
    xof_ctx
}

pub fn hash_i(output: &mut [u8], seed: &[u8]) {
    let mut ctx = Sha3_512::new();
    Digest::update(&mut ctx, seed);
    Digest::update(&mut ctx, &[HQC_I_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
}

// SHA3-256( ek_kem || domain ) → 32 bytes
pub fn hash_h(output: &mut [u8; SEED_BYTES], ek_kem: &[u8]) {
    let mut ctx = Sha3_256::new();
    Digest::update(&mut ctx, ek_kem);
    Digest::update(&mut ctx, &[HQC_H_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
}

// SHA3-512( H(ek_kem) || m || salt || domain ) → SHARED_SECRET_BYTES + SEED_BYTES bytes
pub fn hash_g(output: &mut [u8], hash_ek_kem: &[u8], m: &[u8], salt: &[u8]) {
    let mut ctx = Sha3_512::new();
    Digest::update(&mut ctx, hash_ek_kem);
    Digest::update(&mut ctx, m);
    Digest::update(&mut ctx, salt);
    Digest::update(&mut ctx, &[HQC_G_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
}

// SHA3-256( H(ek_kem) || sigma || u || v || salt || domain ) → 32 bytes
pub fn hash_j(output: &mut [u8; SHARED_SECRET_BYTES], hash_ek_kem: &[u8], sigma: &[u8], u: &[u8], v: &[u8], salt: &[u8]) {
    let mut ctx = Sha3_256::new();
    Digest::update(&mut ctx, hash_ek_kem);
    Digest::update(&mut ctx, sigma);
    Digest::update(&mut ctx, u);
    Digest::update(&mut ctx, v);
    Digest::update(&mut ctx, salt);
    Digest::update(&mut ctx, &[HQC_J_FCT_DOMAIN]);
    output.copy_from_slice(&ctx.finalize());
}