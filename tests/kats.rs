use hqc::kem;
use hqc::parameters::*;
use hqc::symmetric;

const KAT_RSP: &str = include_str!("PQCkemKAT_2321.rsp");

#[test]
fn test_kat() {
    let mut seed: Option<Vec<u8>> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut sk: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;
    let mut ss :Option<Vec<u8>> = None;
    for line in KAT_RSP.lines() {
        if let Some(val) = line.strip_prefix("seed = ") {
            seed = Some(hex::decode(val).unwrap());
        }else if let Some(val) = line.strip_prefix("pk = ") {
            pk = Some(hex::decode(val).unwrap());
        }else if let Some(val) = line.strip_prefix("sk = ") {
            sk = Some(hex::decode(val).unwrap());
        }else if let Some(val) = line.strip_prefix("ct = ") {
            ct = Some(hex::decode(val).unwrap());
        }else if let Some(val) = line.strip_prefix("ss = ") {
            ss = Some(hex::decode(val).unwrap());
        }

        if let (Some(s), Some(p), Some(_k), Some(_c), Some(_shared)) = (&seed, &pk, &sk, &ct, &ss)
        {
            let mut ctx = hqc::symmetric::prng_init(s, &[]);
            let mut ek_kem = vec![0u8; PUBLIC_KEY_BYTES];
            let mut dk_kem = vec![0u8; SECRET_KEY_BYTES];
            hqc::kem::crypto_kem_keypair(&mut ek_kem, &mut dk_kem, &mut ctx);
            assert_eq!(ek_kem, *p);
            seed = None; pk = None; sk = None; ct = None; ss = None;
        }
    }
}