//!
//! winternitz is a small crate implementing a quantum-resistant one-time signature
//! scheme, the `LDWM_SHA256_M20_W8` variant of LDWM (but not MTS) as described in
//! https://tools.ietf.org/html/draft-mcgrew-hash-sigs-02.
//!
//! ## Usage
//!
//! ***Each private key may only be used to sign ONE message. Signing multiple
//! messages with a single key could reveal your private key data.***
//!
//! ```
//! extern crate rand;
//! extern crate winternitz;
//!
//! use rand::{thread_rng, RngCore};
//!
//! fn main() {
//! 	// Fill up the space of a new private key with entropy.
//! 	let mut privkey = [0; winternitz::PRIVKEY_SIZE];
//! 	thread_rng().fill_bytes(&mut privkey);
//!
//! 	// Generate your public key from your private key.
//! 	let mut pubkey = [0; winternitz::PUBKEY_SIZE];
//! 	winternitz::derive_pubkey(&privkey, &mut pubkey).unwrap();
//!
//! 	// Sign a message.
//! 	let msg = b"squeamish ossifrage";
//! 	let mut sig = [0; winternitz::SIG_SIZE];
//! 	winternitz::sign(&privkey, msg, &mut sig).unwrap();
//!
//! 	// Verify a signature.
//! 	assert!(winternitz::verify(&pubkey, msg, &sig).unwrap());
//! }
//! ```

#![cfg_attr(not(feature="utils"), no_std)]

extern crate crypto;
extern crate byteorder;

use byteorder::{BigEndian, WriteBytesExt};

use crypto::digest::Digest;
use crypto::sha2::Sha256;

// These are the parameters that define LDWM_SHA256_M20_W8 (cf. §3.2 and §3.3). It should be ok to
// change them to values of other LDWM variants as described in the spec, but there are no tests
// for that.
//
// Originally I had planned to make Winternitz accept different parameters without editing the
// source, however because of Rust issue #34344, it's not really possible to do this without using
// a macro, which would have made the code much less clear.
//
// the length in bytes of each element of an LDWM signature
const PARAMETER_M: usize = 20;
// the length in bytes of the result of the hash function
const PARAMETER_N: usize = 32;
// the Winternitz parameter (1-8, higher being slower verification and smaller signatures)
const PARAMETER_W: usize = 4;
// the number of `m`-byte string elements that make up the LDWM signature
const PARAMETER_P: usize = 67;
// the number of left-shift bits used in the checksum function C
const PARAMETER_LS: usize = 4;
// a collision-resistant hash function implementing `crypto::digest::Digest`
#[allow(non_camel_case_types)]
type PARAMETER_H = Sha256;
// a one way (preimage resistant) hash function implementing `crypto::digest::Digest`
#[allow(non_camel_case_types)]
type PARAMETER_F = Sha256;

/// The size (in bytes) of a public key
pub const PUBKEY_SIZE: usize = PARAMETER_N;
/// The size (in bytes) of a private key
pub const PRIVKEY_SIZE: usize = PARAMETER_P * PARAMETER_N;
/// The size (in bytes) of a signature
pub const SIG_SIZE: usize = PARAMETER_P * PARAMETER_M;

/// This gets the `index`-th value of `msg` split into `bitlength` pieces.
/// It is described in §2.1.2.
///
/// # Panics
///
/// This function panics if index is out of bounds, or bitlength is not in the set {1, 2, 4, 8}.
fn coef(msg: &[u8], index: usize, bitlength: usize) -> u8 {
    match bitlength {
        8 => {
            msg[index]
        },
        4 => {
            let ix = index/2;
            let byte = msg[ix];
            match index % 2 {
                0 => byte >> 4,
                1 => byte & 0xf,
                _ => unreachable!(),
            }
        },
        2 => {
            let ix = index/4;
            let byte = msg[ix];
            match index % 4 {
                0 => byte >> 6,
                1 => (byte >> 4) & 0x3,
                2 => (byte >> 2) & 0x3,
                3 => byte & 0x3,
                _ => unreachable!(),
            }
        },
        1 => {
            let ix = index/8;
            let byte = msg[ix];
            match index % 8 {
                0 => byte >> 7,
                1 => (byte >> 6) & 0x1,
                2 => (byte >> 5) & 0x1,
                3 => (byte >> 4) & 0x1,
                4 => (byte >> 3) & 0x1,
                5 => (byte >> 2) & 0x1,
                6 => (byte >> 1) & 0x1,
                7 => byte & 0x1,
                _ => unreachable!(),
            }
        }
        _ => unimplemented!()
    }
}

/// A checksum is used to ensure that any forgery attempt that manipulates the elements of an
/// existing signature will be detected.
/// The security property that it provides is detailed in §8.
/// The checksum algorithm itself is described in §3.6.
/// This function will panic! if `msg_hash` is not the right length for `H`'s output.
fn checksum(msg_hash: &[u8]) -> u16 {
    assert_eq!(msg_hash.len(), PARAMETER_N);

    let u = 8 * PARAMETER_N / PARAMETER_W; // ceil is unnecessary because of the assertion
    let mut sum = 0;
    for i in 0..u {
        sum = sum + 2u16.pow(PARAMETER_W as u32) - 1 - (coef(msg_hash, i, PARAMETER_W) as u16);
    }
    sum << (PARAMETER_LS as u16)
}

/// Generate a public key from private entropy `privkey`.
///
/// # Arguments
///
/// * `privkey` is private entropy that must have length of `PRIVKEY_SIZE`
/// * `pubkey` is a mutable slice of size `PUBKEY_SIZE`, which we will clobber with the public key
///
/// # Returns
///
/// This function returns the generated public key `Ok(())` on success, or an `Err` if `privkey` is
/// of incorrect length.
pub fn derive_pubkey(privkey: &[u8], pubkey: &mut [u8]) -> Result<(), &'static str> {
    // This is defined in §3.5.

    assert!(PARAMETER_N >= PARAMETER_M);

    if privkey.len() != PRIVKEY_SIZE {
        Err("privkey is of incorrect length")?;
    }

    if pubkey.len() != PUBKEY_SIZE {
        Err("pubkey is of incorrect length")?;
    }

    let mut inner_hasher = PARAMETER_F::new();
    let mut outer_hasher = PARAMETER_H::new();
    assert!(inner_hasher.output_bytes() >= PARAMETER_M);
    assert_eq!(outer_hasher.output_bytes(), PARAMETER_N);

    let e = 2u32.pow(PARAMETER_W as u32) - 1;
    // for ( i = 0; i < p; i = i + 1 ) {
    for x_i in privkey.chunks(PARAMETER_N) {
        let mut y_i = [0; PARAMETER_M];
        y_i.copy_from_slice(&x_i[..PARAMETER_M]);

        // y[i] = F^e(x[i])
        for _ in 0..e {
            inner_hasher.reset();

            let mut y_i_untruncated = [0; PARAMETER_N];
            inner_hasher.input(&y_i);
            inner_hasher.result(&mut y_i_untruncated);

            y_i.copy_from_slice(&y_i_untruncated[..PARAMETER_M]);
        }

        // This corresponds to the y[i] part of H(y[0] || y[1] || ... || y[p-1])
        outer_hasher.input(&y_i);

        // PoQua compatibility
        if cfg!(feature="poqua-token") {
            outer_hasher.input(&[0; 32 - PARAMETER_M]);
        }
    }

    outer_hasher.result(pubkey);
    Ok(())
}

/// Sign a message `msg` with `privkey`, returning the signature.
///
/// # Arguments
///
/// * `privkey` is private entropy that must have length of `PRIVKEY_SIZE`
/// * `msg` is the message to be signed. It may have any length.
/// * `sig` is a mutable slice of size `SIG_SIZE`, which we will clobber with the signature
///
/// # Danger
///
/// Calling this function more than once with the same `privkey` can reveal the value of
/// `privkey`!
///
/// # Returns
///
/// This function returns the signature `Ok(())` on success, or an `Err` if `privkey` or `sig` is of
/// an incorrect length.
pub fn sign(privkey: &[u8], msg: &[u8], sig: &mut [u8]) -> Result<(), &'static str> {
    if privkey.len() != PRIVKEY_SIZE {
        Err("privkey is of incorrect length")?;
    }
    if sig.len() != SIG_SIZE {
        Err("sig is of incorrect length")?;
    }

    assert!(PARAMETER_N >= PARAMETER_M);

    // V = ( H(message) || C(H(message)) )
    let mut h_m = [0; PARAMETER_N];
    let mut hasher = PARAMETER_H::new();
    assert_eq!(hasher.output_bytes(), PARAMETER_N);
    hasher.input(msg);
    hasher.result(&mut h_m);
    let mut v = [0; PARAMETER_N+2];
    v[..PARAMETER_N].copy_from_slice(&h_m);
    v.split_at_mut(PARAMETER_N).1.write_u16::<BigEndian>(checksum(&h_m)).unwrap();

    let mut hasher = PARAMETER_F::new();
    for ((i, y_i_long), sig_i) in privkey.chunks(PARAMETER_N).enumerate().zip(sig.chunks_mut(PARAMETER_M)) {
        let a = coef(&v, i, PARAMETER_W);
        let mut y_i = [0; PARAMETER_M];
        y_i.copy_from_slice(&y_i_long[..PARAMETER_M]);
        for _ in 0..a {
            hasher.reset();
            hasher.input(&y_i);
            let mut y_i_long = [0; PARAMETER_N];
            hasher.result(&mut y_i_long);
            y_i.copy_from_slice(&y_i_long[..PARAMETER_M]);
        }
        sig_i.copy_from_slice(&y_i);
    }

    Ok(())
}

/// Verify a signature `sig` of message `msg` from public key `pubkey`.
///
/// # Arguments
///
/// * `pubkey` is a public key of length `PARAMETER_N`
/// * `msg` is the message to be verified. It may be of any length.
/// * `sig` is the signature. It must be of length `PARAMETER_P * PARAMETER_N`.
///
/// # Returns
///
/// This function returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not, or
/// an `Err` if `pubkey` or `sig` are of incorrect length.
pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, &'static str> {
    if pubkey.len() != PUBKEY_SIZE {
        Err("pubkey is of invalid length")?;
    }
    if sig.len() != SIG_SIZE {
        Err("sig is of invalid length")?;
    }

    // V = ( H(message) || C(H(message)) )
    let mut h_m = [0; PARAMETER_N];
    let mut hasher = PARAMETER_H::new();
    assert_eq!(hasher.output_bytes(), PARAMETER_N);
    hasher.input(msg);
    hasher.result(&mut h_m);
    let mut v = [0; PARAMETER_N+2];
    {
        let (left, mut right) = v.split_at_mut(PARAMETER_N);
        left.copy_from_slice(&h_m);
        right.write_u16::<BigEndian>(checksum(&h_m)).unwrap();
    }

    let mut inner_hasher = PARAMETER_F::new();
    let mut outer_hasher = PARAMETER_H::new();
    for (i, z_i_long) in sig.chunks(PARAMETER_M).enumerate() {
        let a = 2u8.pow(PARAMETER_W as u32) - 1 - coef(&v, i, PARAMETER_W);
        let mut z_i = [0; PARAMETER_M];
        z_i.copy_from_slice(&z_i_long[..PARAMETER_M]);
        for _ in 0..a {
            inner_hasher.reset();
            inner_hasher.input(&z_i);
            let mut z_i_long = [0; PARAMETER_N];
            inner_hasher.result(&mut z_i_long);
            z_i.copy_from_slice(&z_i_long[..PARAMETER_M]);
        }
        outer_hasher.input(&z_i);

        // PoQua compatibility
        if cfg!(feature="poqua-token") {
            outer_hasher.input(&[0; 32 - PARAMETER_M]);
        }
    }

    let mut hash = [0; PARAMETER_N];
    outer_hasher.result(&mut hash);

    if hash == pubkey {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(feature="utils")]
pub mod util {
    extern crate std;

    use std::error::Error;
    use std::str;

    /// Format a string of bytes into a hex string.
    ///
    /// ```
    /// assert_eq!(winternitz::util::format_bytes(&[0x48, 0x69, 0x2e]), "0x48692e");
    /// ```
    pub fn format_bytes(bytes: &[u8]) -> String {
        let mut s = String::from("0x");
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Change a formatted bytestring into a string of bytes.
    ///
    /// ```
    /// assert_eq!(winternitz::util::deformat_bytes("0x48692e").unwrap(), vec![0x48, 0x69, 0x2e]);
    /// assert_eq!(winternitz::util::deformat_bytes("123456").unwrap(), vec![0x12, 0x34, 0x56]);
    /// assert!(winternitz::util::deformat_bytes("invalid").is_err());
    /// ```
    pub fn deformat_bytes(bytestr: &str) -> Result<Vec<u8>, Box<Error>> {
        let mut out = Vec::new();

        if bytestr.is_empty() || bytestr == "0x" {
            return Ok(out);
        }

        if bytestr.len() % 2 != 0 {
            Err("invalid bytestr length")?;
        }

        let bs = match &bytestr[0..2] {
            "0x" => {
                if bytestr.len() < 4 {
                    Err("invalid bytestr")?;
                }
                &bytestr[2..]
            },
            _ => bytestr,
        };

        for c in bs.as_bytes().chunks(2) {
            let v = str::from_utf8(c)?;
            out.push( u8::from_str_radix(v, 16)? );
        }

        Ok(out)
    }
}

#[test]
fn test_coef() {
    let a = [0x8c, 0x9f, 0xa4, 0xba, 0xa8];
    assert_eq!(0x8c, coef(&a, 0, 8));
    assert_eq!(0xa4, coef(&a, 2, 8));
    assert_eq!(0xa8, coef(&a, 4, 8));
    assert_eq!(0x08, coef(&a, 0, 4));
    assert_eq!(0x0f, coef(&a, 3, 4));
    assert_eq!(0x0a, coef(&a, 7, 4));
    assert_eq!(0x08, coef(&a, 9, 4));
    assert_eq!(0b10, coef(&a, 0, 2));
    assert_eq!(0b11, coef(&a, 2, 2));
    assert_eq!(0b01, coef(&a, 5, 2));
    assert_eq!(0b00, coef(&a, 3, 2));
    assert_eq!(0b01, coef(&a, 0, 1));
    assert_eq!(0b00, coef(&a, 7, 1));
    assert_eq!(0b00, coef(&a, 9, 1));
    assert_eq!(0b01, coef(&a, 5, 1));
}

#[test]
fn test_checksum() {
    let msg = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a];
    let mut hash = [0; 32];
    let mut hasher = Sha256::new();
    hasher.input(&msg);
    hasher.result(&mut hash);
    let cs = checksum(&hash);
    // It looks like PARAMETER_LS is set to 0 in §B.3 where this test case is provided.
    assert_eq!(cs, 0x1cc << 4);
}

#[cfg(test)]
mod tests {
    use super::*;

    // This is the OTS Private Key 0 defined in §B.2 Table 4
    const OTS_PRIVKEY_0: &[u8] =
        &[0xbf, 0xb7, 0x57, 0x38, 0x3f, 0xb0, 0x8d, 0x32, 0x46, 0x29, 0x11, 0x5a, 0x84, 0xda, 0xf0, 0x0b, 0x18, 0x8d, 0x56, 0x95, 0x30, 0x3c, 0x83, 0xc1, 0x84, 0xe1, 0xec, 0x7a, 0x50, 0x1c, 0x43, 0x1f, 0x7c, 0xe6, 0x28, 0xfb, 0x82, 0x00, 0x3a, 0x28, 0x29, 0xaa, 0xb7, 0x08, 0x43, 0x27, 0x87, 0xd0, 0xfc, 0x73, 0x5a, 0x29, 0xd6, 0x71, 0xc7, 0xd7, 0x90, 0x06, 0x8b, 0x45, 0x3d, 0xc8, 0xc9, 0x13, 0x81, 0x74, 0x92, 0x94, 0x61, 0x32, 0x9d, 0x15, 0x06, 0x8a, 0x46, 0x45, 0xa3, 0x44, 0x12, 0xbd, 0x44, 0x6d, 0x4c, 0x9e, 0x75, 0x74, 0x63, 0xa7, 0xd5, 0x16, 0x4e, 0xfd, 0x50, 0xe0, 0x5c, 0x93, 0xf2, 0x83, 0xf3, 0x48, 0x0d, 0xf6, 0x68, 0xde, 0x4d, 0xaa, 0x74, 0xbb, 0x0e, 0x4c, 0x55, 0x31, 0x5b, 0xc0, 0x0f, 0x7d, 0x00, 0x8b, 0xb6, 0x31, 0x1e, 0x59, 0xa5, 0xbb, 0xca, 0x91, 0x0f, 0xd7, 0xe6, 0x27, 0x08, 0xea, 0xf9, 0xc1, 0x38, 0x01, 0x62, 0x25, 0x63, 0x78, 0x03, 0x02, 0xa0, 0x68, 0x0b, 0xa9, 0xd3, 0x9c, 0x07, 0x8d, 0xaa, 0x5e, 0xbc, 0x31, 0x60, 0xe1, 0xd8, 0x0a, 0x1e, 0xa7, 0x1f, 0x00, 0x2e, 0xfa, 0xd2, 0xbf, 0xb4, 0x27, 0x5e, 0x37, 0x6a, 0xf7, 0x13, 0x81, 0x29, 0xe3, 0x3e, 0x88, 0xcf, 0x75, 0x12, 0xec, 0x1d, 0xcd, 0xc7, 0xdf, 0x8d, 0x52, 0x70, 0xbc, 0x0f, 0xd7, 0x8e, 0xd5, 0xa7, 0x03, 0xe9, 0x20, 0x06, 0x58, 0xd1, 0x8b, 0xc4, 0xc0, 0x5d, 0xd0, 0xca, 0x8a, 0x35, 0x64, 0x48, 0xa2, 0x6f, 0x3f, 0x4f, 0xe4, 0xe0, 0x41, 0x8b, 0x52, 0xbd, 0x67, 0x50, 0xa2, 0xc7, 0x4e, 0x56, 0xd6, 0x14, 0x50, 0xc5, 0x38, 0x7e, 0x86, 0xdd, 0xad, 0x5a, 0x81, 0x21, 0xc8, 0x8b, 0x1b, 0xc4, 0x63, 0xe6, 0x4f, 0x24, 0x8a, 0x1f, 0x1d, 0x91, 0xd9, 0x50, 0x95, 0x77, 0x26, 0x62, 0x9f, 0x18, 0xb6, 0xa2, 0xa4, 0xea, 0x65, 0xff, 0xf4, 0xcf, 0x75, 0x8b, 0x57, 0x33, 0x3f, 0xe1, 0xd3, 0x4a, 0xf0, 0x5b, 0x1c, 0xd7, 0x76, 0x36, 0x96, 0x89, 0x9c, 0x98, 0x69, 0x59, 0x5f, 0x17, 0x41, 0xc3, 0x1f, 0xdb, 0xb4, 0x86, 0x47, 0x12, 0xf6, 0xb1, 0x7f, 0xad, 0xc0, 0x5d, 0x45, 0x92, 0x6c, 0x83, 0x1c, 0x7a, 0x75, 0x5b, 0x7d, 0x7a, 0xf5, 0x7a, 0xc3, 0x16, 0xba, 0x6c, 0x2a, 0xe5, 0x9a, 0x7b, 0x81, 0x49, 0x0c, 0x5d, 0x13, 0x33, 0xa9, 0xcd, 0xd4, 0x8b, 0x9c, 0xb3, 0x64, 0x56, 0x82, 0x15, 0x17, 0xa3, 0xa1, 0x3c, 0xb7, 0xa8, 0xed, 0x38, 0x1d, 0x4d, 0x5f, 0x35, 0x45, 0x3b, 0xa9, 0x7f, 0xe8, 0xb2, 0x96, 0x7d, 0xd7, 0x4c, 0x8b, 0x10, 0xf3, 0x1f, 0xc5, 0xf5, 0x27, 0xa2, 0x3b, 0x89, 0xc1, 0x26, 0x62, 0x02, 0xa4, 0xd7, 0xc2, 0x81, 0xe1, 0xf4, 0x1f, 0xa0, 0x20, 0xa2, 0x62, 0xa9, 0x28, 0x7c, 0xc9, 0x79, 0xaa, 0xa5, 0x92, 0x25, 0xd7, 0x5d, 0xf5, 0x1b, 0x82, 0x57, 0xb9, 0x2e, 0x78, 0x0d, 0x1a, 0xb1, 0x4c, 0x4a, 0xc3, 0xec, 0xda, 0xc5, 0x8f, 0x12, 0x80, 0x9d, 0xfe, 0x0a, 0xf1, 0xa3, 0xd9, 0x06, 0x43, 0x38, 0xd9, 0x6c, 0xb8, 0xea, 0xe8, 0x8b, 0xaa, 0x6a, 0x69, 0x26, 0x55, 0x38, 0x87, 0x3b, 0x4c, 0x17, 0x26, 0x5f, 0xa9, 0xd5, 0x73, 0xbc, 0xff, 0xde, 0x9c, 0x5c, 0x6a, 0x5c, 0x6a, 0x27, 0x4e, 0xab, 0xe9, 0x0e, 0xd2, 0xa8, 0xe6, 0x14, 0x8c, 0x72, 0x01, 0x96, 0xd2, 0x37, 0xa8, 0x39, 0xaa, 0xf5, 0x86, 0x8a, 0xf8, 0xda, 0x4d, 0x08, 0x29, 0x5d, 0xe8, 0x1e, 0xc1, 0x70, 0x90, 0xa8, 0x2c, 0xb7, 0x22, 0xf6, 0x16, 0x36, 0x2d, 0x38, 0x08, 0x30, 0xf0, 0x48, 0x41, 0x19, 0x1e, 0x44, 0xf1, 0xf8, 0x1b, 0x98, 0x80, 0x16, 0x4b, 0x14, 0xcd, 0xc0, 0xd0, 0x47, 0x00, 0x06, 0x04, 0x10, 0x5b, 0xad, 0x65, 0x7d, 0x9f, 0xa2, 0xf9, 0xef, 0x10, 0x1c, 0xfd, 0x94, 0x90, 0xf4, 0x66, 0x8b, 0x70, 0x0d, 0x73, 0x8f, 0x2f, 0xa9, 0xe1, 0xd1, 0x1a, 0xf4, 0x52, 0x97, 0xef, 0x31, 0x09, 0x41, 0xe1, 0xe8, 0x55, 0xf9, 0x79, 0x68, 0x12, 0x9b, 0xb1, 0x73, 0x37, 0x91, 0x93, 0x91, 0x9f, 0x7b, 0x0f, 0xee, 0x9c, 0x03, 0x7a, 0xe5, 0x07, 0xc2, 0xd2, 0x46, 0xef, 0x43, 0xa8, 0x77, 0xf0, 0x23, 0xe5, 0xe6, 0x6b, 0xbc, 0xd4, 0xf0, 0x6b, 0x83, 0x9f, 0x3b, 0xfb, 0x2b, 0x64, 0xde, 0x25, 0xcd, 0x67, 0xd1, 0x94, 0x6b, 0x07, 0x11, 0x98, 0x91, 0x29, 0x46, 0xe2, 0xa5, 0x99, 0x86, 0x1b, 0xd9, 0xe8, 0x72, 0x2a, 0xd1, 0xb5, 0x5b, 0x8f, 0x01, 0x39, 0x30, 0x5f, 0xcf, 0x8b, 0x60, 0x77, 0xd5, 0x45, 0xd4, 0x48, 0x8c, 0x4b, 0xcb, 0x65, 0x2f, 0x29, 0xe1, 0xad, 0x4d, 0x2d, 0x29, 0x69, 0x71, 0xe4, 0xb0, 0xb7, 0xa5, 0x7d, 0xe3, 0x05, 0x77, 0x9e, 0x82, 0x31, 0x95, 0x87, 0xb5, 0x8d, 0x3e, 0xf4, 0xda, 0xeb, 0x08, 0xf6, 0x30, 0xbd, 0x56, 0x84, 0x7a, 0x07, 0xfa, 0x7a, 0xed, 0x97, 0xcb, 0x54, 0xae, 0x42, 0x0a, 0x0e, 0x6a, 0x58, 0xa1, 0x53, 0x38, 0x11, 0x0f, 0x77, 0x43, 0xca, 0xb8, 0x35, 0x33, 0x71, 0xf8, 0xca, 0x71, 0x0a, 0x44, 0x09, 0x40, 0x60, 0x1f, 0x6c, 0x4b, 0x35, 0x36, 0x2d, 0xd4, 0x94, 0x8d, 0x56, 0x87, 0xb5, 0xcb, 0x6b, 0x5e, 0xc8, 0xb2, 0xec, 0x59, 0xc2, 0xf0, 0x6f, 0xd5, 0x0f, 0x89, 0x19, 0xeb, 0xea, 0xae, 0x92, 0xa0, 0x61, 0xb0, 0xba, 0x9f, 0x49, 0x3c, 0x49, 0x91, 0xbe, 0x5c, 0xd3, 0xa9, 0xd1, 0x53, 0x60, 0xa9, 0xeb, 0x94, 0xf6, 0xf7, 0xad, 0xc2, 0x8d, 0xdd, 0xf1, 0x74, 0x07, 0x4f, 0x3d, 0xf3, 0xc4, 0xcf, 0x15, 0x46, 0xa8, 0x14, 0xff, 0x16, 0x09, 0x9c, 0xeb, 0xf1, 0xfe, 0x0d, 0xb1, 0xac, 0xe5, 0x1c, 0x27, 0x2f, 0xda, 0x98, 0x46, 0xfb, 0xb5, 0x35, 0x81, 0x59, 0x24, 0xb0, 0x07, 0x7f, 0xa4, 0xcb, 0xb0, 0x6f, 0x13, 0x15, 0x5c, 0xe4, 0xe5, 0x6c, 0x85, 0xa3, 0x26, 0x61, 0xc9, 0x01, 0x42, 0x8b, 0x63, 0x0a, 0x4c, 0x37, 0xea, 0x5c, 0x70, 0x62, 0x15, 0x6f, 0x07, 0xf6, 0xb3, 0xef, 0xff, 0x11, 0x81, 0xee, 0x7f, 0xc0, 0x33, 0x42, 0x41, 0x50, 0x94, 0xe3, 0x61, 0x91, 0xeb, 0x45, 0x0a, 0x11, 0xcd, 0xea, 0x9c, 0x6f, 0x6c, 0xdc, 0x34, 0xde, 0x79, 0xce, 0xe0, 0xba, 0x5b, 0xf2, 0x30, 0xe9, 0xf1, 0xd4, 0x29, 0xb3, 0x43, 0xbb, 0x89, 0x78, 0x81, 0xd2, 0xa1, 0x9e, 0xf3, 0x63, 0xcd, 0x1a, 0xb4, 0x11, 0x7c, 0xba, 0xad, 0x54, 0xdc, 0x29, 0x2b, 0x74, 0xb8, 0xaf, 0x9f, 0x5c, 0xf2, 0x87, 0xf3, 0x4b, 0x25, 0x51, 0xef, 0x54, 0x2f, 0x57, 0x9f, 0xa6, 0x55, 0x35, 0xc5, 0x03, 0x6f, 0x80, 0xeb, 0x83, 0xbe, 0x4c, 0x89, 0x82, 0x66, 0xff, 0xc5, 0x31, 0xda, 0x2e, 0x1a, 0x91, 0x22, 0x9b, 0x4b, 0x46, 0x78, 0x52, 0xfe, 0x33, 0xa0, 0x3a, 0x87, 0x25, 0x72, 0x70, 0x73, 0x42, 0xfd, 0xdd, 0xea, 0xe6, 0x48, 0x41, 0x22, 0x51, 0x86, 0xba, 0xbf, 0x35, 0x3f, 0xa2, 0xa0, 0xcd, 0x09, 0x19, 0xd5, 0x8c, 0xd2, 0x40, 0xab, 0x5c, 0x80, 0xbe, 0x6d, 0xdf, 0x5f, 0x60, 0xd1, 0x81, 0x59, 0x2d, 0xca, 0x2b, 0xe4, 0x01, 0x18, 0xc1, 0xfd, 0xd4, 0x6e, 0x0f, 0x14, 0xdf, 0xfb, 0xcc, 0x7d, 0x5c, 0x9a, 0xd3, 0x86, 0x54, 0x7b, 0xa8, 0x29, 0x39, 0xe4, 0x9c, 0x9c, 0x74, 0xa8, 0xec, 0xcf, 0x1c, 0xea, 0x60, 0xaa, 0x32, 0x7b, 0x5d, 0x2d, 0x0a, 0x66, 0xb1, 0xca, 0x48, 0x91, 0x2d, 0x6d, 0xf4, 0x90, 0x83, 0xe5, 0x02, 0x40, 0x0f, 0xfa, 0xe9, 0x27, 0x3c, 0x6d, 0xe9, 0x2a, 0x30, 0x1e, 0x7b, 0xda, 0x15, 0x37, 0xca, 0xb0, 0x85, 0xe5, 0xad, 0xfa, 0x9e, 0xb7, 0x46, 0xe8, 0xec, 0xa9, 0x40, 0x74, 0xe1, 0x81, 0x2d, 0x69, 0x54, 0x3c, 0xe3, 0xc1, 0xce, 0x70, 0x6f, 0x6e, 0x0b, 0x45, 0xf5, 0xf2, 0x6f, 0x4e, 0xf3, 0x9b, 0x34, 0xca, 0xa7, 0x09, 0x33, 0x5f, 0xd7, 0x1e, 0x8f, 0xc0, 0x12, 0x56, 0x61, 0x2b, 0x0c, 0xa8, 0x39, 0x8e, 0x97, 0xb2, 0x47, 0xae, 0x56, 0x4b, 0x74, 0xb1, 0x38, 0x39, 0xb3, 0xb1, 0xcf, 0x0a, 0x0d, 0xd8, 0xba, 0x62, 0x9a, 0x2c, 0x58, 0x35, 0x5f, 0x84, 0xba, 0xb3, 0x98, 0x9f, 0x00, 0xfd, 0x2c, 0x32, 0x7b, 0xbf, 0xb3, 0x5a, 0x21, 0x8c, 0xc3, 0xce, 0x49, 0xd6, 0xb3, 0x4c, 0xbf, 0x8b, 0x6e, 0x89, 0x19, 0xe9, 0x0c, 0x4e, 0xff, 0x40, 0x0c, 0xa9, 0x96, 0xb5, 0x2a, 0x5d, 0x39, 0x5a, 0x56, 0x15, 0xb7, 0x3d, 0xae, 0x65, 0x58, 0x6a, 0xc5, 0xc8, 0x7f, 0x9d, 0xd3, 0xb9, 0xb3, 0xf8, 0x2d, 0xbf, 0x50, 0x9b, 0x58, 0x81, 0xf0, 0x64, 0x3f, 0xa8, 0x5d, 0x05, 0xca, 0x4c, 0x64, 0x4e, 0x1c, 0x41, 0xcc, 0xda, 0xed, 0xbd, 0x24, 0x15, 0xd4, 0xf0, 0x9b, 0x4a, 0x1b, 0x94, 0x0b, 0x51, 0xfe, 0x82, 0x3d, 0xff, 0x76, 0x17, 0xb8, 0xee, 0x83, 0x04, 0xd9, 0x6a, 0xab, 0x95, 0xef, 0x62, 0x48, 0xe2, 0x35, 0xd9, 0x1d, 0x0f, 0x23, 0xb6, 0x47, 0x27, 0xa6, 0x67, 0x5a, 0xdf, 0xc6, 0x4e, 0xfe, 0xa7, 0x2f, 0x6f, 0x8b, 0x4a, 0x47, 0x99, 0x6c, 0x0d, 0xfd, 0x9c, 0x38, 0x4d, 0x52, 0xd3, 0xac, 0x27, 0xc4, 0xf4, 0x89, 0x8f, 0xcc, 0x15, 0xe8, 0x3a, 0xc1, 0x82, 0xf9, 0x7e, 0xa6, 0x3f, 0x7d, 0x48, 0x92, 0x83, 0xe2, 0xcc, 0x7e, 0x6e, 0xd1, 0x80, 0xc8, 0x6e, 0xae, 0xd6, 0xa9, 0xe3, 0xfb, 0xe5, 0xb2, 0x62, 0xc1, 0xfa, 0x1f, 0x09, 0x9f, 0x7c, 0x35, 0xec, 0xe7, 0x1d, 0x9e, 0x46, 0x7f, 0xab, 0x7a, 0x37, 0x1d, 0xbc, 0xf4, 0x00, 0xb5, 0x44, 0xf4, 0x62, 0xb3, 0x71, 0x9a, 0x2e, 0xd8, 0x77, 0x81, 0x55, 0x63, 0x8f, 0xf8, 0x14, 0xdb, 0xf4, 0x2b, 0x10, 0x7b, 0xb5, 0x24, 0x6e, 0xe3, 0xdd, 0x82, 0xab, 0xf9, 0x77, 0x87, 0xe6, 0xa6, 0x9e, 0x01, 0x46, 0x70, 0x91, 0x2e, 0x3e, 0xb7, 0x49, 0x36, 0xeb, 0xb6, 0x41, 0x68, 0xb4, 0x47, 0xe4, 0x25, 0x22, 0xb5, 0x7c, 0x25, 0x40, 0xac, 0x4b, 0x49, 0xb9, 0xae, 0x35, 0x6c, 0x01, 0xec, 0xa6, 0x2b, 0x41, 0x10, 0x96, 0xe0, 0xca, 0x16, 0x58, 0x78, 0x30, 0xd3, 0xac, 0xd6, 0x73, 0xe8, 0x58, 0x86, 0x3f, 0xed, 0xc4, 0xce, 0xa0, 0x46, 0x58, 0x7c, 0xba, 0x05, 0x56, 0xd2, 0xbf, 0x98, 0x84, 0xa7, 0x39, 0x17, 0xc7, 0x47, 0x30, 0x58, 0x2e, 0x8e, 0x18, 0x15, 0xb8, 0xa0, 0x7b, 0x18, 0x96, 0x2a, 0xc0, 0x5e, 0x50, 0x0e, 0x04, 0x56, 0x76, 0xbe, 0x3f, 0x14, 0x95, 0xfc, 0xfa, 0x18, 0xca, 0xa4, 0xab, 0x61, 0xe6, 0x96, 0x2f, 0xe3, 0x9a, 0x25, 0x5d, 0xbf, 0x8a, 0x46, 0xd2, 0x51, 0x10, 0x0d, 0x12, 0x7f, 0xab, 0x08, 0xdb, 0x59, 0x51, 0x26, 0x53, 0x60, 0x7b, 0xda, 0x24, 0x30, 0x2c, 0x9b, 0x91, 0x0c, 0xa5, 0x16, 0x41, 0x3f, 0x37, 0x6b, 0x9e, 0xba, 0x4b, 0x0d, 0x57, 0x1b, 0x22, 0x25, 0x3c, 0x2a, 0x96, 0x46, 0x13, 0x1a, 0xc9, 0xa2, 0xaf, 0x5f, 0x61, 0x5f, 0x73, 0x22, 0xb8, 0xfc, 0x1b, 0x4c, 0xe6, 0x27, 0xc7, 0x7a, 0xd3, 0x5a, 0x21, 0xea, 0x9d, 0xed, 0x2c, 0xce, 0x91, 0xb3, 0x75, 0x8a, 0x75, 0x82, 0x24, 0xe3, 0x5c, 0xf2, 0x91, 0x81, 0x53, 0xa5, 0x13, 0xd6, 0x4c, 0xc1, 0x90, 0x2d, 0x8e, 0x8c, 0x02, 0xd9, 0x44, 0x25, 0x81, 0xd7, 0xe0, 0x53, 0xa2, 0x79, 0x8a, 0xa8, 0x4d, 0x77, 0xa7, 0x4b, 0x6e, 0x7f, 0x2c, 0xc5, 0x09, 0x6d, 0x50, 0x64, 0x6c, 0x89, 0x0f, 0xb3, 0xf4, 0x7e, 0x2e, 0x8e, 0x2d, 0xcd, 0xd8, 0x90, 0xea, 0x00, 0x93, 0x4b, 0x9d, 0x82, 0x34, 0x83, 0x0d, 0xbc, 0x4a, 0x30, 0xac, 0x99, 0x6b, 0x14, 0x4f, 0x12, 0xb3, 0xe4, 0x63, 0xc7, 0x7f, 0x81, 0x88, 0xd1, 0xec, 0xfc, 0x6a, 0xe6, 0x11, 0x89, 0x11, 0xf2, 0xb9, 0xb3, 0xa6, 0xc7, 0xa1, 0xe5, 0xf9, 0x09, 0xaa, 0x8b, 0x5c, 0x0a, 0xab, 0x8c, 0x69, 0xf1, 0xa7, 0xd4, 0x36, 0xc3, 0x07, 0xca, 0x42, 0xd9, 0x85, 0x97, 0x4c, 0x7b, 0x87, 0x0b, 0xc7, 0x64, 0x94, 0x60, 0x4e, 0xff, 0x49, 0x26, 0x76, 0xc9, 0x42, 0xc6, 0xcb, 0x7c, 0x75, 0xd4, 0x93, 0x88, 0x05, 0x88, 0x5d, 0xd0, 0x54, 0xbe, 0x58, 0x85, 0x1e, 0xbe, 0x56, 0x60, 0x57, 0xe1, 0xee, 0x16, 0xb8, 0xc6, 0x04, 0xa4, 0x73, 0x4c, 0x37, 0x3a, 0xf6, 0x22, 0x66, 0x0b, 0x2a, 0x82, 0x35, 0x7a, 0xc6, 0xef, 0xfb, 0x45, 0x66, 0xc2, 0x2d, 0x49, 0x3f, 0x7a, 0x56, 0x42, 0xfc, 0xeb, 0xa2, 0x40, 0x4d, 0xbe, 0xfa, 0x8f, 0x95, 0x63, 0x23, 0xfa, 0xc8, 0x7f, 0xac, 0x42, 0x5f, 0x6d, 0xe8, 0xd2, 0x3c, 0x9e, 0x8b, 0x20, 0xca, 0x1a, 0x76, 0xc1, 0xff, 0xa4, 0x67, 0x90, 0x61, 0x73, 0xfd, 0x02, 0x45, 0xb0, 0xcd, 0x66, 0x39, 0xe6, 0x01, 0x3c, 0xa7, 0x9c, 0x4e, 0xd9, 0x24, 0x26, 0xee, 0x69, 0xff, 0x5b, 0xee, 0xac, 0x0b, 0xbc, 0x6c, 0x0c, 0xb7, 0x80, 0x8f, 0x37, 0x9a, 0xf1, 0xb7, 0xb7, 0x32, 0x74, 0x36, 0xad, 0x65, 0xc0, 0x54, 0x58, 0xf2, 0xd0, 0xa6, 0x92, 0x3c, 0x33, 0x3e, 0x51, 0x29, 0xc4, 0xc9, 0x96, 0x71, 0xfb, 0xb0, 0x44, 0x88, 0xc3, 0xc0, 0x88, 0xdc, 0x5e, 0x63, 0xd1, 0x3e, 0x6a, 0x70, 0x10, 0x36, 0x61, 0x09, 0xca, 0x4c, 0x5f, 0x4b, 0x0a, 0x8d, 0x37, 0x78, 0x01, 0x87, 0xe2, 0xe9, 0x93, 0x0e, 0xae, 0xc1, 0x08, 0x11, 0x56, 0x9d, 0x4d, 0x72, 0xe3, 0xa1, 0xba, 0xf7, 0x1a, 0x88, 0x6b, 0x75, 0xeb, 0xa6, 0xdc, 0x07, 0xed, 0x02, 0x7a, 0xf0, 0xb2, 0xbe, 0xff, 0xa7, 0x1f, 0x9b, 0x43, 0xc8, 0xf5, 0x52, 0x9b, 0xe3, 0xb7, 0xa1, 0x92, 0x12, 0xe8, 0xba, 0xa9, 0x70, 0xd2, 0x42, 0x0b, 0xf4, 0x12, 0x3f, 0x67, 0x82, 0x67, 0xf9, 0x6c, 0x1c, 0x3e, 0xf2, 0x6a, 0xb6, 0x10, 0xcb, 0x00, 0x61, 0x17, 0x2b, 0xa1, 0xba, 0x0b, 0x70, 0x1e, 0xea, 0xfe, 0x00, 0x69, 0x2d, 0x1e, 0xb9, 0x01, 0x81, 0x8c, 0xca, 0xef, 0xae, 0xb8, 0xf7, 0x99, 0x39, 0x5d, 0xa8, 0x17, 0x11, 0x76, 0x6d, 0x1f, 0x43, 0xfe, 0x1f, 0x8c, 0x15, 0x82, 0x52, 0x08, 0xf3, 0xa2, 0x13, 0x46, 0xb8, 0x94, 0xb3, 0xd9, 0x4e, 0x4f, 0x3a, 0xa2, 0x9c, 0xbc, 0x19, 0x4a, 0x7b, 0x2c, 0x8a, 0x81, 0x0c, 0x4c, 0x50, 0x90, 0x42, 0x2e, 0x81, 0xc6, 0x6c, 0xc9, 0x14, 0xea, 0x1b, 0x0f, 0xa5, 0x94, 0x2f, 0xe9, 0x78, 0x0d, 0x54, 0x8c, 0x0b, 0x33, 0x0e, 0x3b, 0xf7, 0x3f, 0x0c, 0xb0, 0xbd, 0xa4, 0xbc, 0x9c, 0x9e, 0x6f, 0xf4, 0xfc, 0x34, 0x53, 0xae, 0xc5, 0xcc, 0x19, 0xa6, 0xa4, 0xbd, 0xa4, 0xbc, 0x25, 0x93, 0x16, 0x04, 0x70, 0x4b, 0xf4, 0x38, 0x6c, 0xd6, 0x57, 0x80, 0xc6, 0xe7, 0x32, 0x14, 0xc1, 0xda, 0x85, 0xba, 0x4e, 0x80, 0x00, 0xc5, 0x87, 0xdc, 0x91, 0x78, 0x88, 0xe7, 0xe3, 0xd8, 0x17, 0x67, 0x2c, 0x0a, 0xef, 0x81, 0x27, 0x88, 0xcc, 0x85, 0x79, 0xaf, 0xa7, 0xe9, 0xb2, 0xe5, 0x66, 0x30, 0x90, 0x03, 0xba, 0x66, 0x7c, 0xa0, 0xe4, 0x4a, 0x86, 0x01, 0xa0, 0xfd, 0xe8, 0x25, 0xd4, 0xd2, 0xcf, 0x1b, 0xb9, 0xcf, 0x46, 0x70, 0x41, 0xe0, 0x4a, 0xf8, 0x4c, 0x9d, 0x0c, 0xd9, 0xfd, 0x8d, 0xc7, 0x84, 0x49, 0x65, 0xdb, 0x75, 0xf8, 0x1c, 0x8a, 0x59, 0x66, 0x80, 0x75, 0x3c, 0xe7, 0x0a, 0x94, 0xc6, 0x15, 0x62, 0x53, 0xbb, 0x42, 0x69, 0x47, 0xde, 0x1d, 0x76, 0x62, 0xdd, 0x7e, 0x05, 0xe9, 0xa8, 0x2c, 0x23, 0xcc, 0x3e, 0x5c, 0xa3, 0x7d, 0xec, 0x27, 0x9c, 0x50, 0x61, 0x01, 0xa3, 0xd8, 0xd9, 0xf1, 0xe4, 0xf9, 0x9b, 0x2a, 0x33, 0x74, 0x1b, 0x59, 0xf8, 0xbd, 0xdb, 0xa7, 0x45, 0x54, 0x19]

    ;
    // This is a concatencation of the values in §B.3 Table 10
    const EXPECTED_SIG_A: &[u8] =
        &[0xbf, 0xb7, 0x57, 0x38, 0x3f, 0xb0, 0x8d, 0x32, 0x46, 0x29, 0x11, 0x5a, 0x84, 0xda, 0xf0, 0x0b, 0x18, 0x8d, 0x56, 0x95, 0x4a, 0xf0, 0x79, 0xe8, 0x85, 0xdd, 0xfd, 0x32, 0x45, 0xf2, 0x97, 0x78, 0xd2, 0x65, 0xe8, 0x68, 0xa3, 0xbf, 0xea, 0xa4, 0xfb, 0xad, 0x19, 0x28, 0xbf, 0xc5, 0x7b, 0x22, 0xbc, 0xd9, 0x49, 0x19, 0x24, 0x52, 0x29, 0x3d, 0x07, 0xd6, 0xb9, 0xad, 0xb9, 0x80, 0x63, 0xe1, 0x84, 0xb4, 0xcb, 0x94, 0x9a, 0x51, 0xe1, 0xbb, 0x76, 0xd9, 0x9d, 0x42, 0x49, 0xc0, 0xb4, 0x48, 0xe6, 0x27, 0x08, 0xea, 0xf9, 0xc1, 0x38, 0x01, 0x62, 0x25, 0x63, 0x78, 0x03, 0x02, 0xa0, 0x68, 0x0b, 0xa9, 0xd3, 0x9c, 0x39, 0x34, 0x3c, 0xba, 0x3f, 0xfa, 0x6d, 0x75, 0x07, 0x4c, 0xe8, 0x98, 0x31, 0xb3, 0xf3, 0x43, 0x61, 0x08, 0x31, 0x8c, 0xfe, 0x08, 0xaa, 0x73, 0x60, 0x7a, 0xec, 0x56, 0x64, 0x18, 0x8a, 0x9d, 0xac, 0xdc, 0x34, 0xa2, 0x95, 0x58, 0x8c, 0x9a, 0xd3, 0x34, 0x63, 0x82, 0x11, 0x95, 0x52, 0xd1, 0xce, 0xb9, 0x2a, 0x78, 0x59, 0x7a, 0x00, 0xc9, 0x56, 0x37, 0x2b, 0xf0, 0xf1, 0xdd, 0x24, 0x5e, 0xc5, 0x87, 0xc0, 0xa7, 0xa1, 0xb7, 0x54, 0xcc, 0x32, 0x7b, 0x27, 0xc8, 0x39, 0xa6, 0xe4, 0x6a, 0xa5, 0xf1, 0x58, 0xad, 0xc1, 0xde, 0xca, 0xf0, 0xc1, 0xed, 0xc1, 0xa3, 0xa5, 0xd8, 0x95, 0x8d, 0x72, 0x66, 0x27, 0xb5, 0x06, 0xd2, 0x99, 0x0f, 0x62, 0xf2, 0x2f, 0x0c, 0x94, 0x3a, 0x41, 0x84, 0x73, 0x67, 0x8e, 0x3f, 0xfd, 0xbf, 0xf4, 0x82, 0xf3, 0x39, 0x0b, 0x8d, 0x6e, 0x52, 0x29, 0xae, 0x9c, 0x5d, 0x4c, 0x3f, 0x45, 0xe1, 0x04, 0x55, 0xd8, 0x24, 0x1a, 0x49, 0x22, 0xdd, 0x5f, 0x9d, 0x3c, 0x89, 0x18, 0x0c, 0xaa, 0x0f, 0x69, 0x52, 0x03, 0xd8, 0xcf, 0x90, 0xf3, 0xc3, 0x59, 0xbe, 0x67, 0x99, 0x9c, 0x40, 0x43, 0xf9, 0x5d, 0xe5, 0xf0, 0x7d, 0x82, 0xb7, 0x41, 0x34, 0x7a, 0x3e, 0xb6, 0xac, 0x0c, 0x25, 0xc4, 0xff, 0xe4, 0x72, 0xd4, 0x8a, 0xde, 0xb3, 0x7c, 0x73, 0x60, 0xda, 0x70, 0x71, 0x14, 0x62, 0x01, 0x3b, 0x7a, 0x4e, 0x5d, 0xe8, 0x1e, 0xc1, 0x70, 0x90, 0xa8, 0x2c, 0xb7, 0x22, 0xf6, 0x16, 0x36, 0x2d, 0x38, 0x08, 0x30, 0xf0, 0x48, 0x41, 0x2f, 0x89, 0x2c, 0x82, 0x4a, 0xf6, 0x5c, 0xc7, 0x49, 0xf9, 0x12, 0xa3, 0x6d, 0xfa, 0x8a, 0xde, 0x2e, 0x4c, 0x3f, 0xd1, 0xb6, 0x44, 0x39, 0x3e, 0x80, 0x30, 0x92, 0x44, 0x03, 0xb5, 0x94, 0xfb, 0x5c, 0xac, 0xd8, 0xb2, 0xd2, 0x88, 0x62, 0xe2, 0x31, 0xb8, 0xd2, 0x90, 0x89, 0x11, 0xdb, 0xbf, 0x5b, 0xa1, 0xf4, 0x79, 0xa8, 0x54, 0x80, 0x89, 0x45, 0xd9, 0xe9, 0x48, 0xa9, 0xa0, 0x22, 0x69, 0xd2, 0x4e, 0xb8, 0xfe, 0xd6, 0xfb, 0x86, 0x10, 0x1c, 0xbd, 0x0d, 0x89, 0x77, 0x21, 0x9f, 0xb1, 0xe4, 0xaa, 0xe6, 0xe6, 0xa9, 0xfe, 0x1b, 0x0d, 0x50, 0x99, 0x51, 0x3f, 0x17, 0x0c, 0x11, 0x1d, 0xee, 0x95, 0x71, 0x4d, 0xd7, 0x9c, 0x16, 0xe7, 0xf2, 0xd4, 0xdd, 0x79, 0x0e, 0x28, 0xba, 0xb0, 0xd5, 0x62, 0x29, 0x8c, 0x86, 0x4e, 0x31, 0xe9, 0xc2, 0x96, 0x78, 0xf0, 0xbb, 0x47, 0x44, 0x59, 0x7e, 0x04, 0x15, 0x6f, 0x53, 0x26, 0x46, 0xc9, 0x8a, 0x0b, 0x42, 0xe8, 0x57, 0xb3, 0x1d, 0x75, 0x74, 0x3f, 0xf0, 0xf9, 0xbc, 0xf2, 0xdb, 0x39, 0xd9, 0xb6, 0x22, 0x41, 0x10, 0xb8, 0xd2, 0x7b, 0x0a, 0x33, 0x6d, 0x93, 0xaa, 0xc0, 0x81, 0xa2, 0xd8, 0x49, 0xc6, 0x12, 0x36, 0x8b, 0x8c, 0xbb, 0x2f, 0xa9, 0x56, 0x3a, 0x91, 0x7b, 0xe0, 0xc9, 0x47, 0x70, 0xa7, 0xbb, 0x12, 0x71, 0x3a, 0x4b, 0xae, 0x80, 0x1f, 0xb3, 0xc1, 0xc4, 0x30, 0x02, 0x91, 0x58, 0x6f, 0xea, 0xad, 0xcf, 0x69, 0x1b, 0x6c, 0xb0, 0x7c, 0x16, 0xc8, 0xa2, 0xed, 0x08, 0x84, 0x66, 0x6e, 0x84, 0xdd, 0x4e, 0x4b, 0x72, 0x0f, 0xb2, 0x51, 0x7c, 0x4b, 0xc6, 0xf9, 0x1c, 0xcb, 0x87, 0x25, 0x11, 0x8e, 0x57, 0x70, 0xc6, 0x49, 0x1f, 0x6e, 0xc6, 0x65, 0xf5, 0x4c, 0x4b, 0x3c, 0xff, 0xaa, 0x02, 0xec, 0x59, 0x4d, 0x31, 0xe6, 0xe2, 0x6c, 0x0e, 0x4f, 0x5a, 0x08, 0x2c, 0x9d, 0x9c, 0x97, 0x14, 0x70, 0x1d, 0xe0, 0xbf, 0x42, 0x6e, 0x9f, 0x89, 0x34, 0x84, 0x61, 0x8c, 0x11, 0xf7, 0x01, 0x73, 0x13, 0xf0, 0xc9, 0x54, 0x9c, 0x5d, 0x41, 0x5a, 0x8a, 0xbc, 0x25, 0x24, 0x30, 0x28, 0x51, 0x4d, 0x68, 0x39, 0xa9, 0x94, 0xfc, 0xcb, 0x9c, 0xb7, 0x62, 0x41, 0xd8, 0x09, 0x14, 0x69, 0x06, 0xa3, 0xd1, 0x3f, 0x89, 0xf1, 0x71, 0xcd, 0x1d, 0x91, 0x63, 0xd7, 0xcd, 0x56, 0x39, 0x36, 0x83, 0x7c, 0x61, 0xd9, 0x7b, 0xb1, 0xa5, 0x33, 0x7c, 0xc0, 0x77, 0xc9, 0x03, 0x4f, 0xfc, 0x0f, 0x92, 0x19, 0x84, 0x1a, 0xa8, 0xe1, 0xed, 0xbf, 0xb6, 0x20, 0x17, 0xef, 0x9f, 0xd1, 0xad, 0x9f, 0x60, 0x34, 0x01, 0x7d, 0x35, 0xc3, 0x38, 0xac, 0x35, 0x77, 0x8d, 0xd6, 0xc4, 0xc1, 0xab, 0xe4, 0x47, 0x2a, 0x4a, 0x1c, 0x39, 0x6b, 0x22, 0xe4, 0xf5, 0xcc, 0x24, 0x28, 0x04, 0x5b, 0x36, 0xd1, 0x37, 0x37, 0xc4, 0x00, 0x75, 0x15, 0x98, 0xcb, 0x57, 0xb7, 0x79, 0xc5, 0xfd, 0x3f, 0x36, 0x1c, 0xd5, 0xde, 0xbc, 0x24, 0x33, 0x03, 0xae, 0x5b, 0xae, 0xfd, 0x29, 0x85, 0x72, 0x98, 0xf2, 0x74, 0xd6, 0xbf, 0x59, 0x5e, 0xad, 0xc8, 0x9e, 0x54, 0x64, 0xcc, 0xf9, 0x60, 0x8a, 0x6c, 0x95, 0xe3, 0x5a, 0x26, 0x81, 0x5a, 0x3a, 0xe9, 0xad, 0x84, 0xa2, 0x44, 0x64, 0xb1, 0x74, 0xa2, 0x93, 0x64, 0xda, 0x18, 0x4a, 0xfe, 0xb3, 0xb9, 0x5b, 0x5b, 0x33, 0x37, 0x59, 0xc0, 0xac, 0xdd, 0x96, 0xce, 0x3f, 0x26, 0x31, 0x4b, 0xb2, 0x2b, 0x32, 0x5a, 0x37, 0xee, 0x5e, 0x34, 0x9b, 0x22, 0xb1, 0x3b, 0x54, 0xb2, 0x4b, 0xe5, 0x14, 0x53, 0x44, 0xe7, 0xb8, 0xf3, 0x4f, 0x77, 0x2c, 0x93, 0xf5, 0x6f, 0xd6, 0x95, 0x8c, 0xe1, 0x35, 0xf0, 0x28, 0x47, 0x99, 0x6c, 0x67, 0xe1, 0xf2, 0xef, 0xd4, 0xf6, 0xd9, 0x1c, 0x57, 0x75, 0x94, 0x06, 0x0b, 0xe3, 0x28, 0xb0, 0x13, 0xc9, 0xe9, 0xb0, 0xe8, 0xa2, 0xe5, 0xd8, 0x71, 0x7e, 0x1a, 0x81, 0xc3, 0x25, 0xcd, 0xcc, 0xac, 0xb6, 0xe9, 0xfd, 0x9e, 0x92, 0xdd, 0x3e, 0x1b, 0xb8, 0x4a, 0xe8, 0x1d, 0xd3, 0x63, 0x72, 0x4e, 0xc6, 0x6c, 0x09, 0x0a, 0x12, 0x28, 0xdf, 0xa1, 0xcd, 0x3d, 0x9c, 0xc8, 0x06, 0xf3, 0x46, 0x64, 0xb4, 0x11, 0x04, 0x76, 0xdd, 0x0b, 0xee, 0xa7, 0x87, 0x14, 0xc5, 0xab, 0x71, 0x27, 0x88, 0x18, 0x79, 0x2c, 0xfa, 0xe2, 0x22, 0x90, 0xe7, 0x40, 0x05, 0x6a, 0x14, 0x4a, 0xf5, 0x0f, 0x0b, 0x10, 0x96, 0x2b, 0x5b, 0xcc, 0x18, 0xfc, 0x82, 0x34, 0xfd, 0x87, 0x04, 0x6a, 0x18, 0x3f, 0x47, 0x32, 0xa5, 0x2b, 0xb7, 0x80, 0x5c, 0xe2, 0x07, 0xee, 0xbd, 0xaf, 0xc5, 0xbd, 0x2f, 0xdc, 0x5e, 0x4e, 0x8d, 0x0e, 0xd7, 0xc4, 0x8c, 0x1b, 0xad, 0x9c, 0x2f, 0x77, 0x93, 0xfc, 0x2c, 0x93, 0x03, 0xb3, 0xf4, 0x7e, 0x2e, 0x8e, 0x2d, 0xcd, 0xd8, 0x90, 0xea, 0x00, 0x93, 0x4b, 0x9d, 0x82, 0x34, 0x83, 0x0d, 0xbc, 0x4a, 0xcd, 0x29, 0x71, 0x9c, 0x56, 0xcd, 0xb5, 0x07, 0x03, 0x0e, 0x61, 0x32, 0x13, 0x21, 0x79, 0xe5, 0x80, 0x7e, 0x1d, 0x3b, 0xf9, 0xed, 0xb9, 0xb3, 0x01, 0x91, 0x62, 0x17, 0xde, 0x0d, 0x74, 0x6a, 0x05, 0x42, 0x31, 0x6b, 0xeb, 0xe9, 0xe8, 0x06, 0x7a, 0x38, 0x01, 0xcb, 0xfe, 0x0c, 0xaf, 0xed, 0x86, 0x3d, 0x81, 0x21, 0x0c, 0x1e, 0xc7, 0x21, 0xee, 0xde, 0x49, 0xe5, 0x5c, 0xab, 0xa3, 0xec, 0x96, 0x0e, 0xfa, 0x21, 0x0f, 0x5f, 0x3e, 0x1c, 0x22, 0xc5, 0x67, 0xca, 0x47, 0x5e, 0xf3, 0xec, 0xf9, 0x11, 0xb5, 0xd1, 0x48, 0xe1, 0xb0, 0x3f, 0xe6, 0x98, 0x3c, 0x53, 0x41, 0x1f, 0x76, 0xea, 0x78, 0x77, 0x23, 0x79, 0x06, 0xda, 0x2b, 0xaa, 0x75, 0xc6, 0xef, 0x75, 0x2b, 0xf5, 0x9f, 0x38, 0x12, 0xfa, 0x04, 0x2f, 0xf8, 0x18, 0x12, 0x09, 0x2b, 0x29, 0xf5, 0xaa, 0x2f, 0x34, 0xaf, 0x51, 0xa7, 0x8a, 0x5f, 0xac, 0x58, 0x60, 0x04, 0xf7, 0x49, 0xc6, 0xe6, 0xdc, 0x55, 0xe0, 0x33, 0xab, 0xab, 0xac, 0x08, 0x45, 0xcc, 0x91, 0x42, 0xe2, 0x4f, 0x9e, 0xf0, 0xa6, 0x41, 0xc5, 0x1c, 0xbe, 0xb6, 0x2d, 0x20, 0x7b, 0xb7, 0x00, 0x07, 0x1f, 0xba, 0x8a, 0x68, 0x31, 0x2c, 0xa2, 0x04, 0xce, 0x4d, 0x99, 0x4c, 0x33, 0x55, 0x1d, 0x5c, 0x00, 0xfa, 0xd9, 0x05, 0xbd, 0xb9, 0x9c, 0x4f, 0x70, 0xec, 0x75, 0x90, 0xa1, 0x0d, 0x3f, 0xf8, 0xca, 0x0d, 0x03, 0xb1, 0x84, 0x5b, 0x5f, 0x88, 0x38, 0xd7, 0x35, 0x14, 0x2f, 0x18, 0x5f, 0x9c, 0xf8, 0xf8, 0xd2, 0xdb, 0x6c, 0x3b, 0x5d, 0x9e, 0x49, 0xe7, 0xed, 0xe4, 0x1c, 0xd9, 0xaa, 0x5a, 0x09, 0xf7, 0x2a, 0x03, 0x84, 0xfd, 0x4f, 0xf5, 0x11, 0xa7, 0x66, 0xb0, 0x27, 0x8d, 0x14, 0xa9, 0xb7, 0xd3, 0x2b, 0xf0, 0x30, 0x7c, 0x07, 0x37, 0xa8, 0xec, 0xf8, 0x2a, 0xb1, 0xca, 0x85, 0x29, 0x6f, 0x35, 0x4e, 0x6e, 0x3d, 0x2a, 0x96, 0xab, 0x49, 0x7c, 0x01, 0xe5, 0xcc, 0xd4, 0x53, 0x0c, 0xf1, 0x7b, 0xb2, 0x9d, 0xb7, 0xdd, 0x8a, 0xaa, 0xf1, 0xcd, 0x11, 0x48, 0x7c, 0xea, 0x0d, 0x13, 0x73, 0x0e, 0xdb, 0x1d, 0xf3, 0x54, 0x7e, 0xf3, 0x41, 0xb3, 0xcf, 0x32, 0x08, 0x75, 0x3b, 0xb1, 0xb6, 0x2d, 0x85, 0xa4, 0xe3, 0xfc, 0x2c, 0xff, 0xe0, 0xb8, 0x90, 0xe1, 0xa9, 0x9d, 0xa4, 0xb2, 0xe0, 0xa9, 0xdd, 0xe4, 0x2f, 0x82, 0xf9, 0x2d, 0x09, 0x46, 0x32, 0x7c, 0xee]
    ;

    // This is OTS Public Key 0 in §B.2 Table 5
    const OTS_PUBKEY_0: &[u8] =
        &[0x2d, 0xb5, 0x5a, 0x72, 0x07, 0x5f, 0xcf, 0xab, 0x5a, 0xed, 0xbe, 0xf7, 0x7b, 0xf6, 0xb3, 0x71, 0xdf, 0xb4, 0x89, 0xd6, 0xe6, 0x1a, 0xd2, 0x88, 0x4a, 0x24, 0x83, 0x45, 0xe6, 0x91, 0x06, 0x18]
    ;

    // This value is given in §B.3 Table 8
    const MSG: &[u8] =
        &[0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a]
    ;

    #[test]
    #[cfg(not(feature="poqua-token"))]
    fn test_derive_pubkey() {
        let mut pubkey = [0; PUBKEY_SIZE];
        derive_pubkey(OTS_PRIVKEY_0, &mut pubkey).unwrap();
        assert!(OTS_PUBKEY_0 == &pubkey[..]);
    }

    #[test]
    #[cfg(not(feature="poqua-token"))]
    fn test_sign() {
        let privkey = OTS_PRIVKEY_0;
        let mut sig = [0; SIG_SIZE];
        sign(&privkey, MSG, &mut sig).unwrap();
        assert!(EXPECTED_SIG_A == &sig[..]);
    }

    #[test]
    fn test_successful_verify() {
        let mut pubkey = [0; PUBKEY_SIZE];
        derive_pubkey(OTS_PRIVKEY_0, &mut pubkey).unwrap();
        let mut sig = [0; SIG_SIZE];
        sign(OTS_PRIVKEY_0, MSG, &mut sig).unwrap();
        assert!(verify(&pubkey, MSG, &sig).unwrap());
    }

    #[test]
    fn test_unsuccessful_verify() {
        let mut pubkey = [0; PUBKEY_SIZE];
        derive_pubkey(OTS_PRIVKEY_0, &mut pubkey).unwrap();
        let mut sig = [0; SIG_SIZE];
        sign(OTS_PRIVKEY_0, MSG, &mut sig).unwrap();

        let mut bad_sig = sig.clone();
        bad_sig[0] = bad_sig[0].wrapping_add(1);
        assert!(!verify(&pubkey, MSG, &bad_sig).unwrap());

        let mut bad_pubkey = pubkey.clone();
        bad_pubkey[0] = bad_pubkey[0].wrapping_add(1);
        assert!(!verify(&bad_pubkey, MSG, &sig).unwrap());

    }
}
