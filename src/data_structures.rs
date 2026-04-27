use crate::parameters::*;

#[derive(Clone, Copy)]
pub struct CiphertextPke {
    pub u: [u64; VEC_N_SIZE_64],
    pub v: [u64; VEC_N1N2_SIZE_64],
}

#[derive(Clone, Copy)]
pub struct RmCodeword {
    pub u32: [u32; 4],
}

impl RmCodeword {
    pub fn as_u8(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.u32.as_ptr() as *const u8, 16)
        }
    }
    
    pub fn as_u8_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.u32.as_mut_ptr() as *mut u8, 16)
        }
    }
}