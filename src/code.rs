use crate::parameters::VEC_N1_SIZE_64;
use crate::reed_muller;
use crate::reed_solomon;
use zeroize::Zeroize;


pub fn code_encode(em: &mut [u64], m: & [u64]){
    let mut tmp = [0u64; VEC_N1_SIZE_64];

    reed_solomon::reed_solomon_encode(&mut tmp, m);
    reed_muller::reed_muller_encode(em, &tmp);

    tmp.zeroize();
}

pub fn code_decode(m: &mut [u64], em: & [u64]){
    let mut tmp = [0u64; VEC_N1_SIZE_64];

    reed_muller::reed_muller_decode(&mut tmp, em);
    reed_solomon::reed_solomon_decode(m, &mut tmp);

    tmp.zeroize();
}