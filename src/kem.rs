use crate::parameters::*;
use crate::symmetric;
use crate::parsing;
use crate::hqc::{hqc_pke_keygen, hqc_pke_encrypt, hqc_pke_decrypt};
use crate::data_structures::CiphertextPke;
use sha3::digest::{ExtendableOutput, XofReader};
use zeroize::Zeroize;

fn ct_is_diff(a: &[u8], b: &[u8]) -> u8 {
    let mut d = 0u8;
    for (ai, bi) in a.iter().zip(b.iter()) {
        d |= ai ^ bi;
    }
    // 0 if equal, 1 if different (constant-time)
    let r = d as u32;
    ((r | r.wrapping_neg()) >> 31) as u8
}

pub fn kem_keypair(ek_kem: &mut [u8; KEM_PUBLIC_KEY_BYTES], dk_kem: &mut [u8; KEM_SECRET_KEY_BYTES]) {
    let mut seed_kem = [0u8; SEED_BYTES];
    rand::RngExt::fill(&mut rand::rng(), &mut seed_kem);
    kem_keypair_from_seed(ek_kem, dk_kem, &seed_kem);
    seed_kem.zeroize();
}

pub fn kem_keypair_from_seed(
    ek_kem: &mut [u8; KEM_PUBLIC_KEY_BYTES],
    dk_kem: &mut [u8; KEM_SECRET_KEY_BYTES],
    seed_kem: &[u8],
) {
    let mut seed_pke = [0u8; SEED_BYTES];
    let mut sigma = [0u8; PARAM_SECURITY_BYTES];
    let mut ek_pke = [0u8; PUBLIC_KEY_BYTES];
    let mut dk_pke = [0u8; SECRET_KEY_BYTES];

    // Dérive seed_pke et sigma depuis seed_kem via XOF
    let ctx = symmetric::xof_init(seed_kem);
    let mut reader = ctx.finalize_xof();
    reader.read(&mut seed_pke);
    reader.read(&mut sigma);

    hqc_pke_keygen(&mut ek_pke, &mut dk_pke, &seed_pke);

    // ek_kem = ek_pke
    ek_kem.copy_from_slice(&ek_pke);

    // dk_kem = ek_pke || dk_pke || sigma || seed_kem
    let mut off = 0;
    dk_kem[off..off + PUBLIC_KEY_BYTES].copy_from_slice(&ek_pke);
    off += PUBLIC_KEY_BYTES;
    dk_kem[off..off + SECRET_KEY_BYTES].copy_from_slice(&dk_pke);
    off += SECRET_KEY_BYTES;
    dk_kem[off..off + PARAM_SECURITY_BYTES].copy_from_slice(&sigma);
    off += PARAM_SECURITY_BYTES;
    dk_kem[off..off + SEED_BYTES].copy_from_slice(seed_kem);

    seed_pke.zeroize();
    sigma.zeroize();
    dk_pke.zeroize();
}

pub fn kem_encaps(
    ct: &mut [u8; KEM_CIPHERTEXT_BYTES],
    k: &mut [u8; SHARED_SECRET_BYTES],
    ek_kem: &[u8; KEM_PUBLIC_KEY_BYTES],
) {
    let mut m = [0u8; PARAM_SECURITY_BYTES];
    let mut salt = [0u8; SALT_BYTES];
    rand::RngExt::fill(&mut rand::rng(), &mut m);
    rand::RngExt::fill(&mut rand::rng(), &mut salt);

    let mut hash_ek = [0u8; SEED_BYTES];
    let mut k_theta = [0u8; SHARED_SECRET_BYTES + SEED_BYTES];
    let mut theta = [0u8; SEED_BYTES];

    symmetric::hash_h(&mut hash_ek, ek_kem);
    symmetric::hash_g(&mut k_theta, &hash_ek, &m, &salt);
    theta.copy_from_slice(&k_theta[SHARED_SECRET_BYTES..]);

    let mut c_pke = CiphertextPke {
        u: [0u64; VEC_N_SIZE_64],
        v: [0u64; VEC_N1N2_SIZE_64],
    };
    let m_u64 = unsafe {
        std::slice::from_raw_parts(m.as_ptr() as *const u64, VEC_K_SIZE_64)
    };
    hqc_pke_encrypt(&mut c_pke, ek_kem, m_u64, &theta);

    parsing::hqc_c_kem_to_string(ct, &c_pke.u, &c_pke.v, &salt);
    k.copy_from_slice(&k_theta[..SHARED_SECRET_BYTES]);

    m.zeroize();
    k_theta.zeroize();
    theta.zeroize();
}

pub fn kem_decaps(
    k: &mut [u8; SHARED_SECRET_BYTES],
    ct: &[u8; KEM_CIPHERTEXT_BYTES],
    dk_kem: &[u8; KEM_SECRET_KEY_BYTES],
) {
    // Parse dk_kem
    let mut off = 0;
    let ek_pke = &dk_kem[off..off + PUBLIC_KEY_BYTES];
    off += PUBLIC_KEY_BYTES;
    let dk_pke = &dk_kem[off..off + SECRET_KEY_BYTES];
    off += SECRET_KEY_BYTES;
    let sigma = &dk_kem[off..off + PARAM_SECURITY_BYTES];

    // Parse ciphertext
    let mut c_pke = CiphertextPke {
        u: [0u64; VEC_N_SIZE_64],
        v: [0u64; VEC_N1N2_SIZE_64],
    };
    let mut salt = [0u8; SALT_BYTES];
    parsing::hqc_c_kem_from_string(&mut c_pke.u, &mut c_pke.v, &mut salt, ct);

    // Déchiffre → m'
    let mut m_prime = [0u8; PARAM_SECURITY_BYTES];
    {
        let m_u64 = unsafe {
            std::slice::from_raw_parts_mut(m_prime.as_mut_ptr() as *mut u64, VEC_K_SIZE_64)
        };
        hqc_pke_decrypt(m_u64, dk_pke, &c_pke);
    }

    // Re-calcule K' et θ'
    let mut hash_ek = [0u8; SEED_BYTES];
    let mut k_theta_prime = [0u8; SHARED_SECRET_BYTES + SEED_BYTES];
    let mut theta_prime = [0u8; SEED_BYTES];
    symmetric::hash_h(&mut hash_ek, ek_pke);
    symmetric::hash_g(&mut k_theta_prime, &hash_ek, &m_prime, &salt);
    theta_prime.copy_from_slice(&k_theta_prime[SHARED_SECRET_BYTES..]);

    // Re-chiffre → ct'
    let mut c_pke_prime = CiphertextPke {
        u: [0u64; VEC_N_SIZE_64],
        v: [0u64; VEC_N1N2_SIZE_64],
    };
    let m_u64 = unsafe {
        std::slice::from_raw_parts(m_prime.as_ptr() as *const u64, VEC_K_SIZE_64)
    };
    hqc_pke_encrypt(&mut c_pke_prime, ek_pke, m_u64, &theta_prime);

    // K_bar (clé de rejet)
    let mut k_bar = [0u8; SHARED_SECRET_BYTES];
    let u_bytes = unsafe { std::slice::from_raw_parts(c_pke.u.as_ptr() as *const u8, VEC_N_SIZE_BYTES) };
    let v_bytes = unsafe { std::slice::from_raw_parts(c_pke.v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES) };
    symmetric::hash_j(&mut k_bar, &hash_ek, sigma, u_bytes, v_bytes, &salt);

    // Compare ct et ct' en temps constant
    let u_prime_bytes = unsafe { std::slice::from_raw_parts(c_pke_prime.u.as_ptr() as *const u8, VEC_N_SIZE_BYTES) };
    let v_prime_bytes = unsafe { std::slice::from_raw_parts(c_pke_prime.v.as_ptr() as *const u8, VEC_N1N2_SIZE_BYTES) };
    let mut differ = 0u8;
    differ |= ct_is_diff(u_bytes, u_prime_bytes);
    differ |= ct_is_diff(v_bytes, v_prime_bytes);
    differ |= ct_is_diff(&salt, &salt); // sel identique par construction

    // CT-select : differ=0 → mask=0xFF → K=K', differ=1 → mask=0x00 → K=K_bar
    let mask = (differ as u32).wrapping_sub(1) as u8;
    let k_prime = &k_theta_prime[..SHARED_SECRET_BYTES];
    for i in 0..SHARED_SECRET_BYTES {
        k[i] = (k_prime[i] & mask) ^ (k_bar[i] & !mask);
    }

    m_prime.zeroize();
    k_theta_prime.zeroize();
    theta_prime.zeroize();
    k_bar.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_correctness() {
        let mut ek = [0u8; KEM_PUBLIC_KEY_BYTES];
        let mut dk = [0u8; KEM_SECRET_KEY_BYTES];
        let mut ct = [0u8; KEM_CIPHERTEXT_BYTES];
        let mut k1 = [0u8; SHARED_SECRET_BYTES];
        let mut k2 = [0u8; SHARED_SECRET_BYTES];

        kem_keypair(&mut ek, &mut dk);
        kem_encaps(&mut ct, &mut k1, &ek);
        kem_decaps(&mut k2, &ct, &dk);

        assert_eq!(k1, k2, "KEM : la clé partagée ne correspond pas !");
    }

    #[test]
    fn test_kem_rejection() {
        let mut ek = [0u8; KEM_PUBLIC_KEY_BYTES];
        let mut dk = [0u8; KEM_SECRET_KEY_BYTES];
        let mut ct = [0u8; KEM_CIPHERTEXT_BYTES];
        let mut k1 = [0u8; SHARED_SECRET_BYTES];
        let mut k2 = [0u8; SHARED_SECRET_BYTES];

        kem_keypair(&mut ek, &mut dk);
        kem_encaps(&mut ct, &mut k1, &ek);

        // Corrompt le chiffré
        ct[0] ^= 1;

        kem_decaps(&mut k2, &ct, &dk);
        assert_ne!(k1, k2, "KEM : rejection devrait donner une clé différente !");
    }

    #[test]
    fn test_kem_deterministic() {
        let seed = [42u8; SEED_BYTES];
        let mut ek1 = [0u8; KEM_PUBLIC_KEY_BYTES];
        let mut dk1 = [0u8; KEM_SECRET_KEY_BYTES];
        let mut ek2 = [0u8; KEM_PUBLIC_KEY_BYTES];
        let mut dk2 = [0u8; KEM_SECRET_KEY_BYTES];

        kem_keypair_from_seed(&mut ek1, &mut dk1, &seed);
        kem_keypair_from_seed(&mut ek2, &mut dk2, &seed);

        assert_eq!(ek1, ek2, "KEM keypair : non déterministe !");
        assert_eq!(dk1, dk2, "KEM keypair : non déterministe !");
    }
}
