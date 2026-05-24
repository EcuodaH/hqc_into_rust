use crate::data_structures::CiphertextKem;
use crate::data_structures::CiphertextPke;
use crate::parameters::*;
use crate::symmetric;
use crate::vector;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

pub fn hqc_ek_pke_from_string(h: &mut [u64], s: &mut [u64], ek_pke: &[u8]) {
    let ek_xof_ctx = symmetric::xof_init(&ek_pke[..SEED_BYTES]);  
    let mut ek_reader = ek_xof_ctx.finalize_xof();
    vector::vect_set_random(&mut ek_reader, h);

    let s_bytes = unsafe {
        std::slice::from_raw_parts_mut(s.as_mut_ptr() as *mut u8, VEC_N_SIZE_BYTES)
    };
    s_bytes.copy_from_slice(&ek_pke[SEED_BYTES..SEED_BYTES + VEC_N_SIZE_BYTES]);
}

pub fn hqc_dk_pke_from_string(y: &mut [u64], dk_pke: &[u8]) {
    let dk_xof_ctx = symmetric::xof_init(&dk_pke[..SEED_BYTES]);
    let mut dk_reader = dk_xof_ctx.finalize_xof();
    vector::vect_sample_fixed_weight1(&mut dk_reader, y, PARAM_OMEGA);
    drop(dk_reader);
}

pub fn hqc_c_kem_to_string(ct: &mut [u8], c_kem: &CiphertextKem){
    let u_bytes = unsafe {
        std::slice::from_raw_parts(c_kem.c_pke.u.as_ptr() as *const u8, VEC_N_SIZE_BYTES)
    };
    let v_bytes = unsafe {
        std::slice::from_raw_parts(c_kem.c_pke.v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES)
    };
    ct[0..VEC_N_SIZE_BYTES].copy_from_slice(&u_bytes[..VEC_N_SIZE_BYTES]);
    ct[VEC_N_SIZE_BYTES..(VEC_N_SIZE_BYTES+VEC_N1N2_SIZE_BYTES)].copy_from_slice(&v_bytes[..VEC_N1N2_SIZE_BYTES]);
    ct[(VEC_N_SIZE_BYTES+VEC_N1N2_SIZE_BYTES)..(VEC_N_SIZE_BYTES+VEC_N1N2_SIZE_BYTES+SALT_BYTES)].copy_from_slice(&c_kem.salt[..SALT_BYTES]);
}

pub fn hqc_c_kem_from_string(c_pke: &mut CiphertextPke, salt: &mut [u8], ct: &[u8]){
    unsafe {
        let u_dst = std::slice::from_raw_parts_mut(c_pke.u.as_mut_ptr() as *mut u8, VEC_N_SIZE_BYTES);
        u_dst.copy_from_slice(&ct[0..VEC_N_SIZE_BYTES]);

        let v_dst = std::slice::from_raw_parts_mut(c_pke.v.as_mut_ptr() as *mut u8, VEC_N1N2_SIZE_BYTES);
        v_dst.copy_from_slice(&ct[VEC_N_SIZE_BYTES..VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES]);
    }
    salt.copy_from_slice(&ct[(VEC_N_SIZE_BYTES+VEC_N1N2_SIZE_BYTES)..(VEC_N_SIZE_BYTES+VEC_N1N2_SIZE_BYTES+SALT_BYTES)]);
}