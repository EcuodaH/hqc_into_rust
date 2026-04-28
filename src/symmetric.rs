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

