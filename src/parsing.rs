use crate::parameters::*;
use crate::symmetric;
use crate::vector;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};


pub fn hqc_ek_pke_from_string(h: &mut [u64], s: &mut [u64], ek_pke: &[u8]) {
    let ek_xof_ctx = symmetric::xof_init(&ek_pke[..SEED_BYTES]);  // ← seulement la seed !
    let mut ek_reader = ek_xof_ctx.finalize_xof();
    vector::vect_set_random(&mut ek_reader, h);

    let s_bytes = unsafe {
        std::slice::from_raw_parts_mut(s.as_mut_ptr() as *mut u8, VEC_N_SIZE_BYTES)
    };
    s_bytes.copy_from_slice(&ek_pke[SEED_BYTES..SEED_BYTES + VEC_N_SIZE_BYTES]);
}

pub fn hqc_dk_pke_from_string(y: &mut [u64], dk_pke: &[u8]) {
    let dk_xof_ctx = symmetric::xof_init(dk_pke);
    let mut dk_reader = dk_xof_ctx.finalize_xof();
    vector::vect_sample_fixed_weight1(&mut dk_reader, y, PARAM_OMEGA);
    drop(dk_reader);
}

