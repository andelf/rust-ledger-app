use nanos_sdk::bindings::CX_LAST;
use nanos_sdk::bindings::{cx_hash, cx_hash_sha256, cx_keccak_init};
use nanos_sdk::bindings::{cx_hash_t, cx_sha3_t};

pub fn hash_sha256(input: &[u8], out: &mut [u8]) -> usize {
    let written = unsafe {
        cx_hash_sha256(
            input.as_ptr(),
            input.len() as _,
            out.as_mut_ptr(),
            out.len() as _,
        )
    };
    written as _
}

pub fn hash_keccak256(input: &[u8], out: &mut [u8]) -> usize {
    unsafe {
        let mut ctx = cx_sha3_t::default();
        cx_keccak_init(&mut ctx, 256);
        cx_hash(
            &mut ctx as *mut cx_sha3_t as *mut cx_hash_t,
            CX_LAST as _,
            input.as_ptr(),
            input.len() as _,
            out.as_mut_ptr(),
            out.len() as _,
        ) as _
    }
}
