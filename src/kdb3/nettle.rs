extern crate libc;

use std::mem;


#[repr(C)]
pub struct NettleContextAES {
    keys: [u32; 60],
    nrounds: libc::c_uint,
}


#[repr(C)]
pub struct NettleContextSHA256 {
    state: [u32; 8],
    count_low: u32,
    count_high: u32,
    block: [u8; 64],
    index: libc::c_uint,
}


#[repr(C)]
pub struct NettleContextAESCBC {
    ctx: NettleContextAES,
    iv: [u8; 16],
}


extern {
    fn memcpy(dst: *mut libc::c_void, src: *const libc::c_void, size: libc::size_t);
}


type NettleCryptFunc = unsafe extern fn (ctx: *const NettleContextAES, length: libc::c_uint, dst: *mut u8, src: *const u8);

#[link(name="nettle")]
extern {
    fn nettle_aes_set_encrypt_key(ctx: *mut NettleContextAES, length: libc::c_uint, key: *const u8);
    fn nettle_aes_set_decrypt_key(ctx: *mut NettleContextAES, length: libc::c_uint, key: *const u8);
    fn nettle_aes_encrypt(ctx: *const NettleContextAES, length: libc::c_uint, dst: *mut u8, src: *const u8);
    fn nettle_aes_decrypt(ctx: *const NettleContextAES, length: libc::c_uint, dst: *mut u8, src: *const u8);

    fn nettle_cbc_decrypt(ctx: *mut libc::c_void, f: NettleCryptFunc, block_size: libc::c_uint, iv: *mut u8, length: libc::c_uint, dst: *mut u8, src: *const u8);

    fn nettle_sha256_init(ctx: *mut NettleContextSHA256);
    fn nettle_sha256_update(ctx: *mut NettleContextSHA256, length: libc::c_uint, data: *const u8);
    fn nettle_sha256_digest(ctx: *mut NettleContextSHA256, length: libc::c_uint, digest: *mut u8);
}


// Inline decrypt based on the KDB3 body format
pub fn aes256_cbc_decrypt<'a>(key: &[u8; 32], iv: &[u8; 16], hash: &[u8; 32], data: &'a mut [u8]) -> Option<&'a [u8]> {

    let mut ctx: NettleContextAESCBC;
    unsafe {
        ctx = mem::uninitialized();
        nettle_aes_set_decrypt_key(&mut ctx.ctx, 32, key.as_ptr());
        memcpy(ctx.iv.as_ptr() as *mut libc::c_void, iv.as_ptr() as *const libc::c_void, 16);
        nettle_cbc_decrypt((&mut ctx as *mut NettleContextAESCBC) as *mut libc::c_void,
                           nettle_aes_decrypt, 16,
                           ctx.iv.as_mut_ptr(),
                           data.len() as libc::c_uint,
                           data.as_mut_ptr(),
                           data.as_ptr());
    }

    let mut size = data.len();

    // Check if removing the padding results in an impossible data size
    // Note that this may simply be a symptom of a bad key
    if (data[size - 1] as usize) >= size {
        println!("Bad size");
        return None;
    }

    size -= data[size - 1] as usize;

    // Verify key by hashing the body
    let check = sha256_digest_new(data, size as u32);
    if &check != hash { // Yes, timing issues.
        println!("Bad hash");
        return None;
    }

    return Some(&data[0..size]);
}


pub fn sha256_digest(src: *const u8, size: u32, dst: *mut u8) {
    let mut sha_ctx: NettleContextSHA256;
    unsafe {
        sha_ctx = mem::uninitialized();
        nettle_sha256_init(&mut sha_ctx);
        nettle_sha256_update(&mut sha_ctx, size, src);
        nettle_sha256_digest(&mut sha_ctx, 32, dst);
    }
}


// Convenience
pub fn sha256_digest_new(src: &[u8], size: u32) -> [u8; 32] {
    let mut key: [u8; 32];
    unsafe {
        key = mem::uninitialized();
    }
    sha256_digest(src.as_ptr(), size, key.as_mut_ptr());
    return key;
}


// KDF algorithm as used by KDB3
//
// Multiple ECB rounds on both halves of the master key
pub fn kdf_ecb_rounds(master_key: &[u8; 32],
                      rounds_key: &[u8; 32],
                      rounds: u32) -> [u8; 32] {
    let mut aes_ctx: NettleContextAES;
    let mut out = master_key.clone();

    unsafe {
        aes_ctx = mem::uninitialized();
        nettle_aes_set_encrypt_key(&mut aes_ctx, 32, rounds_key.as_ptr());
    }

    for _ in 0..rounds {
        unsafe {
            nettle_aes_encrypt(&aes_ctx, 16, out.as_mut_ptr(),            out.as_ptr());
            nettle_aes_encrypt(&aes_ctx, 16, out.as_mut_ptr().offset(16), out.as_ptr().offset(16));
        }
    }

    out
}


pub fn kdf_sha256_final(final_seed: &[u8; 16], out: &mut [u8; 32]) {
    unsafe {
        let mut sha_ctx: NettleContextSHA256 = mem::uninitialized();
        nettle_sha256_init(&mut sha_ctx);
        nettle_sha256_update(&mut sha_ctx, 16, final_seed.as_ptr());
        nettle_sha256_update(&mut sha_ctx, 32, out.as_ptr());
        nettle_sha256_digest(&mut sha_ctx, 32, out.as_mut_ptr());
    }
}
