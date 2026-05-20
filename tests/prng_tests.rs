use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

#[test]
fn test_prng_matches_c() {
    // Reproduction exacte de prng_init du C :
    // shake256_inc_absorb(ctx, seed, 48)
    // shake256_inc_absorb(ctx, NULL, 0)        ← rien absorbé
    // shake256_inc_absorb(ctx, &domain, 1)     ← domain = 0
    // shake256_inc_finalize(ctx)
    
    let seed = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
    
    let mut ctx = Shake256::default();
    Update::update(&mut ctx, &seed);
    // pas d'update pour personalization (NULL/0)
    Update::update(&mut ctx, &[0u8]); // HQC_PRNG_DOMAIN = 0
    
    let mut reader = ctx.finalize_xof();
    let mut seed_kem = [0u8; 32];
    reader.read(&mut seed_kem);
    
    println!("seed_kem obtenu: {}", hex::encode(&seed_kem));
    println!("seed_kem attendu: 9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e7");
    
    assert_eq!(hex::encode(&seed_kem), "9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e7");
}

#[test]
fn test_shake256_basic() {
    // Test basique : qu'est-ce que SHAKE256(seed) donne ?
    let seed = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
    
    // Test 1 : SHAKE256 pur sans rien ajouter
    let mut ctx = sha3::Shake256::default();
    sha3::digest::Update::update(&mut ctx, &seed);
    let mut reader = sha3::digest::ExtendableOutput::finalize_xof(ctx);
    let mut out = [0u8; 32];
    sha3::digest::XofReader::read(&mut reader, &mut out);
    println!("SHAKE256(seed)              = {}", hex::encode(&out));
    
    // Test 2 : SHAKE256(seed || 0x00) — comme ton prng_init avec domain=0
    let mut ctx2 = sha3::Shake256::default();
    sha3::digest::Update::update(&mut ctx2, &seed);
    sha3::digest::Update::update(&mut ctx2, &[0u8]);
    let mut reader2 = sha3::digest::ExtendableOutput::finalize_xof(ctx2);
    let mut out2 = [0u8; 32];
    sha3::digest::XofReader::read(&mut reader2, &mut out2);
    println!("SHAKE256(seed || 0x00)      = {}", hex::encode(&out2));
    
    println!("seed_kem attendu (KAT C)    = 9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e7");
}