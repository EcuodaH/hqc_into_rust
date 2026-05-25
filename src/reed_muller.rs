use crate::parameters::*;
use crate::data_structures::RmCodeword;

pub const MULTIPLICITY: usize = PARAM_N2.div_ceil(128);

#[inline]
fn bit0mask(x: i32) -> i32 {
    -((x) & 1)
}

fn encode(word : &mut RmCodeword, message: i32){
    let mut first_word = bit0mask(message >> 7);
    first_word ^= bit0mask(message >> 0) & 0xaaaaaaaa_u32 as i32;
    first_word ^= bit0mask(message >> 1) & 0xcccccccc_u32 as i32;
    first_word ^= bit0mask(message >> 2) & 0xf0f0f0f0_u32 as i32;
    first_word ^= bit0mask(message >> 3) & 0xff00ff00_u32 as i32;
    first_word ^= bit0mask(message >> 4) & 0xffff0000_u32 as i32;

    word.u32[0] = first_word as u32;

    first_word ^= bit0mask(message >> 5);
    word.u32[1] = first_word as u32;
    first_word ^= bit0mask(message >> 6);
    word.u32[3] = first_word as u32;
    first_word ^= bit0mask(message >> 5);
    word.u32[2] = first_word as u32;
}

fn hadamard(src: &mut [i16; 128], dst: &mut [i16; 128]) {
    for _ in 0..7 {
        for i in 0..64 {
            dst[i] = src[2 * i] + src[2 * i + 1];
            dst[i + 64] = src[2 * i] - src[2 * i + 1];
        }
        src.copy_from_slice(dst);
    }
}

fn expand_and_sum(dest: &mut [i16; 128], src: &[RmCodeword]) {
    for part in 0..4 {
        for bit in 0..32 {
            dest[part * 32 + bit] = ((src[0].u32[part] >> bit) & 1) as i16;
        }
    }

    for copy in 1..src.len() {  // ← src.len() au lieu de MULTIPLICITY !
        for part in 0..4 {
            for bit in 0..32 {
                dest[part * 32 + bit] += ((src[copy].u32[part] >> bit) & 1) as i16;
            }
        }
    }
}

fn find_peaks(transform : &mut [i16; 128]) -> i32{
    let mut peak_abs_value = 0i32;
    let mut peak_value = 0i32;
    let mut peak_pos = 0i32;
    for i in 0..128{
        let t = transform[i];
        let pos_mask: i32 = -((t > 0) as i32);
        let absolute = (pos_mask & (t as i32)) | (!pos_mask & -(t as i32));

        peak_value = if absolute > peak_abs_value {t as i32} else {peak_value};
        peak_pos = if absolute > peak_abs_value {i as i32} else {peak_pos};
        peak_abs_value = if absolute > peak_abs_value {absolute} else {peak_abs_value};    
    }

    peak_pos |= 128 * (peak_value > 0) as i32;
    peak_pos
}

#[cfg_attr(feature = "profiling", inline(never))]
pub fn reed_muller_encode(cdw:&mut [u64], msg: & [u64]){
    let message_array = unsafe {
        std::slice::from_raw_parts(msg.as_ptr() as *const u8, VEC_N1_SIZE_BYTES)
    };

    let code_array = unsafe {
        std::slice::from_raw_parts_mut(cdw.as_mut_ptr() as *mut RmCodeword, VEC_N1_SIZE_BYTES * MULTIPLICITY)
    };

    for i in 0..VEC_N1_SIZE_BYTES{
        let pos:usize = i * MULTIPLICITY;
        encode(&mut code_array[pos], message_array[i] as i32);

        for copy in 1..MULTIPLICITY{
            let codeword_copy = code_array[pos];  
            code_array[pos + copy] = codeword_copy;
        }
    }
}

pub fn reed_muller_decode(msg: &mut [u64], cdw:&[u64]){
    let message_array = unsafe {
        std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, VEC_N1_SIZE_BYTES)
    };
    let code_array = unsafe {
        std::slice::from_raw_parts(cdw.as_ptr() as *const RmCodeword, VEC_N1_SIZE_BYTES * MULTIPLICITY)
    }; 

    for i in 0..VEC_N1_SIZE_BYTES{
        let mut expanded= [0i16; 128];
        expand_and_sum(&mut expanded, &code_array[i * MULTIPLICITY..(i + 1) * MULTIPLICITY]);   

        let mut transform = [0i16;128];
        hadamard(&mut expanded, &mut transform);

        transform[0] -= (64 * MULTIPLICITY) as i16;

        message_array[i] = find_peaks(&mut transform) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    #[test]
    fn test_reed_muller_encode_decode() {
        let mut rng = rand::rng();
        let mut msg = [0u64; VEC_N1_SIZE_64];
        let msg_bytes = unsafe {
            std::slice::from_raw_parts_mut(msg.as_mut_ptr() as *mut u8, PARAM_N1)
        };
        rng.fill(msg_bytes);

        let mut encoded = [0u64; VEC_N1N2_SIZE_64];
        reed_muller_encode(&mut encoded, &msg);

        let mut decoded = [0u64; VEC_N1_SIZE_64];
        reed_muller_decode(&mut decoded, &encoded);

        assert_eq!(msg, decoded, "Reed-Muller encode/decode échoue !");
    }

    #[test]
    fn test_decode_all_bytes() {
        for byte in 0u8..=255 {
            let mut word = RmCodeword { u32: [0u32; 4] };
            encode(&mut word, byte as i32);
            
            let src = vec![word; MULTIPLICITY];
            let mut expanded = [0i16; 128];
            expand_and_sum(&mut expanded, &src);
            
            let mut transform = [0i16; 128];
            hadamard(&mut expanded, &mut transform);
            transform[0] -= 64 * MULTIPLICITY as i16;
            
            let result = find_peaks(&mut transform) as u8;
            assert_eq!(result, byte, "decode(encode({})) = {}", byte, result);
        }
    }
}