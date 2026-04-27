use crate::{gf, parameters::*, tables::*};


fn compute_fft_betas(betas: &mut [u16]){
    for i in 0..(PARAM_M - 1){
        betas[i] = 1 << (PARAM_M - 1 - i);
    }
}

fn compute_subset_sums(subset_sums : &mut [u16], set: &[u16], set_size: usize){
    subset_sums[0] = 0;
    for i in 0..set_size{
        for j in 0..(1 << i){
            subset_sums[(1 << i) + j] = set[i] ^ subset_sums[j];
        }
    }
}

fn radix(f0: &mut [u16], f1: &mut [u16], f: &[u16], m_f: u32){
    match m_f {
        4 =>{
            f0[4] = f[8] ^ f[12];
            f0[6] = f[12] ^ f[14];
            f0[7] = f[14] ^ f[15];
            f1[5] = f[11] ^ f[13];
            f1[6] = f[13] ^ f[14];
            f1[7] = f[15];
            f0[5] = f[10] ^ f[12] ^ f1[5];
            f1[4] = f[9] ^ f[13] ^ f0[5];

            f0[0] = f[0];
            f1[3] = f[7] ^ f[11] ^ f[15];
            f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3];
            f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3];
            f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3];
            f1[2] = f[3] ^ f1[1] ^ f0[3];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }

        3 =>{
            f0[0] = f[0];
            f0[2] = f[4] ^ f[6];
            f0[3] = f[6] ^ f[7];
            f1[1] = f[3] ^ f[5] ^ f[7];
            f1[2] = f[5] ^ f[6];
            f1[3] = f[7];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        2 =>{
            f0[0] = f[0];
            f0[1] = f[2] ^ f[3];
            f1[0] = f[1] ^ f0[1];
            f1[1] = f[3];
        }
        1 => {
            f0[0] = f[0];
            f1[0] = f[1];
        }
        _ => {
            radix_big(f0, f1, f, m_f);
        }
    }
}

fn radix_big(f0: &mut [u16], f1: &mut [u16], f: &[u16], m_f: u32){
    let mut q = [0u16; 2 * (1 << (PARAM_FFT - 2)) + 1];
    let mut r = [0u16; 2 * (1 << (PARAM_FFT - 2)) + 1];

    let mut q0 = [0u16; 1 << (PARAM_FFT - 2)];
    let mut q1 = [0u16; 1 << (PARAM_FFT - 2)];
    let mut r0 = [0u16; 1 << (PARAM_FFT - 2)];
    let mut r1 = [0u16; 1 << (PARAM_FFT - 2)];

    let mut n: usize = 1;
    n <<= m_f -2 ;

    q[..2*n].copy_from_slice(&f[3*n..3*n + 2*n]);
    q[n..n + 2*n].copy_from_slice(&f[3*n..3*n + 2*n]);
    r[..4*n].copy_from_slice(&f[..4*n]);

    for i in 0..n{
        q[i] ^= f[2 * n + i];
        r[n + i] ^= q[i];
    }

    radix(&mut q0,&mut q1,&q,m_f - 1);
    radix(&mut r0,&mut r1,&r,m_f - 1);

    f0[..n].copy_from_slice(&r0[..n]);
    f0[n..2*n].copy_from_slice(&q0[..n]);
    f1[..n].copy_from_slice(&r1[..n]);
    f1[n..2*n].copy_from_slice(&q1[..n]);
}

fn fft_rec(w: &mut [u16], f: &mut [u16], f_coeffs: usize, m: usize, m_f: u32, betas: & [u16]){
    let mut f0 = [0u16; 1 << (PARAM_FFT - 2)];
    let mut f1 = [0u16; 1 << (PARAM_FFT - 2)];
    let mut gammas = [0u16; (PARAM_M -2)];
    let mut deltas = [0u16; (PARAM_M -2)];
    let mut gammas_sums = [0u16; (1 << (PARAM_M -2))];
    let mut u = [0u16; (1 << (PARAM_M -2))];
    let mut v = [0u16; (1 << (PARAM_M -2))];
    let mut tmp = [0u16; (PARAM_M - (PARAM_FFT -1))];

    if m_f == 1{
        for i in 0..m{
            tmp[i] = gf::gf_mul(betas[i], f[1]);
        }

        w[0] = f[0];
        let mut x = 1 as usize;
        for j in 0..m{
            for k in 0..x{
                w[x + k] = w[k] ^ tmp[j];
            }
            x <<= 1;
        }

        return;
    }

    if betas[m - 1] != 1{
        let mut beta_m_pow = 1;
        let mut x = 1;
        x <<= m_f;
        for i in 1..x{
            beta_m_pow = gf::gf_mul(beta_m_pow, betas[m - 1]);
            f[i] = gf::gf_mul(beta_m_pow, f[i]);
        }
    }

    radix(&mut f0, &mut f1, f, m_f);

    for i in 0..(m-1){
        gammas[i] = gf::gf_mul(betas[i], gf::gf_inverse(betas[m - 1]));
        deltas[i] = gf::gf_square(gammas[i]) ^ gammas[i];
    }

    compute_subset_sums(&mut gammas_sums, &gammas, m - 1);

    fft_rec(&mut u, &mut f0, (f_coeffs + 1) / 2, m - 1, m_f - 1, &deltas);

    let mut k= 1;
    k <<= (m - 1) & 0xf ;

    if f_coeffs <= 3{
        w[0] = u[0];
        w[k] = u[0] ^ f1[0];
        for i in 1..k{
            w[i] = u[i] ^ gf::gf_mul(gammas_sums[i], f1[0]);
            w[k + i] = w[i] ^ f1[0];
        }
    }else{
        fft_rec(&mut v, &mut f1, f_coeffs / 2, m - 1, m_f - 1, &deltas);
        w[k..2*k].copy_from_slice(&v[..k]);
        w[0] = u[0];
        w[k] ^= u[0];

        for i in 1..k{
            w[i] = u[i] ^ gf::gf_mul(gammas_sums[i], v[i]);
            w[k + i] ^= w[i];
        }
    }
}

pub fn fft(w: &mut [u16], f: &[u16], f_coeffs: usize){
    let mut betas = [0u16; PARAM_M - 1];
    let mut betas_sums = [0u16; 1 << (PARAM_M - 1)];
    let mut f0 = [0u16; 1 << (PARAM_FFT - 1)];
    let mut f1 = [0u16; 1 << (PARAM_FFT - 1)];
    let mut deltas = [0u16; PARAM_M - 1];
    let mut u = [0u16; 1 << (PARAM_M - 1)];
    let mut v = [0u16; 1 << (PARAM_M - 1)];

    compute_fft_betas(&mut betas);
    compute_subset_sums(&mut betas_sums, &betas, PARAM_M - 1);
    radix(&mut f0,&mut f1,f,PARAM_FFT as u32);

    for i in 0..(PARAM_M - 1){
        deltas[i] = gf::gf_square(betas[i]) ^ betas[i];
    }

    fft_rec(&mut u, &mut f0, (f_coeffs +1) / 2, PARAM_M - 1, (PARAM_FFT - 1) as u32, &deltas);
    fft_rec(&mut v, &mut f1, f_coeffs / 2, PARAM_M - 1, (PARAM_FFT - 1) as u32, &deltas);

    let k = 1 << (PARAM_M - 1);

    w[k..2*k].copy_from_slice(&v[..k]);

    w[0] = u[0];
    w[k] ^= u[0];


    for i in 1..k{
        w[i] = u[i] ^ gf::gf_mul(betas_sums[i], v[i]);
        w[k + i] ^= w[i];        
    }
}

pub fn fft_retrieve_error_poly(error: &mut [u8], w: &[u16]){
    let mut gammas = [0u16; PARAM_M - 1];
    let mut gammas_sums= [0u16; 1 << (PARAM_M - 1)];

    compute_fft_betas(&mut gammas);
    compute_subset_sums(&mut gammas_sums, &mut gammas, PARAM_M - 1);

    let k = 1 << (PARAM_M - 1);
    error[0] ^= (1 ^ (((w[0]).wrapping_neg() as u16) >> 15)) as u8;
    error[0] ^= (1 ^ (((w[k]).wrapping_neg() as u16) >> 15)) as u8;

    for i in 1..k{
        let mut index = PARAM_GF_MUL_ORDER - GF_LOG[gammas_sums[i] as usize] as usize;
        error[index] ^= (1 ^ (((w[i]).wrapping_neg() as u16) >> 15)) as u8;

        index = PARAM_GF_MUL_ORDER - GF_LOG[(gammas_sums[i] ^ 1) as usize] as usize;
        error[index] ^= (1 ^ (((w[k + i]).wrapping_neg() as u16) >> 15)) as u8;

    }
}