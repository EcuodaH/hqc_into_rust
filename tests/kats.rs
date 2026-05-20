use hqc::parameters::*;

const KAT_RSP: &str = include_str!("PQCkemKAT_2321.rsp");

#[test]
fn test_kat() {
    let mut seed: Option<Vec<u8>> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut sk: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;
    let mut ss: Option<Vec<u8>> = None;
    let mut count = 0;

    for line in KAT_RSP.lines() {
        if let Some(val) = line.strip_prefix("seed = ") {
            seed = Some(hex::decode(val).unwrap());
        } else if let Some(val) = line.strip_prefix("pk = ") {
            pk = Some(hex::decode(val).unwrap());
        } else if let Some(val) = line.strip_prefix("sk = ") {
            sk = Some(hex::decode(val).unwrap());
        } else if let Some(val) = line.strip_prefix("ct = ") {
            ct = Some(hex::decode(val).unwrap());
        } else if let Some(val) = line.strip_prefix("ss = ") {
            ss = Some(hex::decode(val).unwrap());
        }

        if let (Some(s), Some(p), Some(k), Some(c), Some(shared)) =
            (&seed, &pk, &sk, &ct, &ss)
        {
            let mut ctx = hqc::symmetric::prng_init(s, &[]);
            let mut ek_kem = vec![0u8; PUBLIC_KEY_BYTES];
            let mut dk_kem = vec![0u8; SECRET_KEY_BYTES];
            let mut ct_computed = vec![0u8; CIPHERTEXT_BYTES];
            let mut ss_computed = vec![0u8; SHARED_SECRET_BYTES];
            let mut ss_decapsed = vec![0u8; SHARED_SECRET_BYTES];

            // Keygen
            hqc::kem::crypto_kem_keypair(&mut ek_kem, &mut dk_kem, &mut ctx);
            assert_eq!(ek_kem, *p, "count {}: ek_kem mismatch", count);
            assert_eq!(dk_kem, *k, "count {}: dk_kem mismatch", count);

            // Encapsulation
            hqc::kem::crypto_kem_enc(&mut ct_computed, &mut ss_computed, &ek_kem, &mut ctx);
            assert_eq!(ct_computed, *c, "count {}: ct mismatch", count);
            assert_eq!(ss_computed, *shared, "count {}: ss mismatch (enc)", count);

            // Décapsulation
            hqc::kem::crypto_kem_dec(&mut ss_decapsed, &ct_computed, &dk_kem);
            assert_eq!(ss_decapsed, *shared, "count {}: ss mismatch (dec)", count);

            count += 1;
            seed = None; pk = None; sk = None; ct = None; ss = None;
        }
    }

    println!("{} KATs passed (keygen + enc + dec)", count);
}