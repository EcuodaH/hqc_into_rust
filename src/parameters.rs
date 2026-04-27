pub const fn bitmask(a: usize, size: usize) -> u64 {
    (1u64 << (a % size)) - 1
}

pub const PARAM_N: usize = 17669;
pub const PARAM_N1: usize = 46;
pub const PARAM_N2: usize = 384;
pub const PARAM_N1N2: usize = 17664;
pub const PARAM_OMEGA: usize = 66;
pub const PARAM_OMEGA_R: usize = 75;
pub const PARAM_OMEGA_E: usize = 75;

pub const PUBLIC_KEY_BYTES: usize = SEED_BYTES + VEC_N_SIZE_BYTES;
pub const SECRET_KEY_BYTES: usize = SEED_BYTES;
pub const CRYPTO_SECRETKEYBYTES: usize = 2321;

pub const VEC_N_SIZE_BYTES: usize = PARAM_N.div_ceil(8);
pub const VEC_N1_SIZE_BYTES: usize = PARAM_N1;

pub const VEC_N_SIZE_64: usize = PARAM_N.div_ceil(64);
pub const VEC_N1_SIZE_64: usize = PARAM_N1.div_ceil(8);
pub const VEC_N1N2_SIZE_64: usize = PARAM_N1N2.div_ceil(64);

pub const VEC_K_SIZE_BYTES: usize = PARAM_K;
pub const VEC_K_SIZE_64: usize = PARAM_K.div_ceil(8);

pub const SEED_BYTES: usize = 32;

pub const UTILS_REJECTION_THRESHOLD: u32 = 16767881;
pub const PARAM_N_MU: u64 = 243079;

pub const PARAM_DELTA: usize = 15;
pub const PARAM_M: usize = 8;
pub const PARAM_GF_MUL_ORDER: usize = 255;
pub const PARAM_K: usize = 16;
pub const PARAM_G: usize = 31;
pub const PARAM_FFT: usize = 4;

pub const PARAM_SECURITY_BYTES: usize = 16;
pub const SALT_BYTES: usize = 16;
pub const SHARED_SECRET_BYTES: usize = 32;

pub const VEC_N1N2_SIZE_BYTES: usize = PARAM_N1N2 / 8;

pub const KEM_PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
pub const KEM_SECRET_KEY_BYTES: usize = PUBLIC_KEY_BYTES + SECRET_KEY_BYTES + PARAM_SECURITY_BYTES + SEED_BYTES;
pub const KEM_CIPHERTEXT_BYTES: usize = VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SALT_BYTES;



