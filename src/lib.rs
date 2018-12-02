// Section numbers refer to https://tools.ietf.org/html/draft-mcgrew-hash-sigs-02

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
        sum = sum + 2u16.pow(PARAMETER_W as u32) - 1 - u16::from(coef(msg_hash, i, PARAMETER_W));
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
        y_i.copy_from_slice(x_i.split_at(PARAMETER_M).0);

        // y[i] = F^e(x[i])
        for _ in 0..e {
            inner_hasher.reset();

            let mut y_i_untruncated = [0; PARAMETER_N];
            inner_hasher.input(&y_i);
            inner_hasher.result(&mut y_i_untruncated);

            y_i.copy_from_slice(y_i_untruncated.split_at(PARAMETER_M).0);
        }

        // This corresponds to the y[i] part of H(y[0] || y[1] || ... || y[p-1])
        outer_hasher.input(&y_i);
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
    {
        let (left, mut right) = v.split_at_mut(PARAMETER_N);
        left.copy_from_slice(&h_m);
        right.write_u16::<BigEndian>(checksum(&h_m)).unwrap();
    }

    let mut hasher = PARAMETER_F::new();
    for ((i, y_i_long), sig_i) in privkey.chunks(PARAMETER_N).enumerate().zip(sig.chunks_mut(PARAMETER_M)) {
        let a = coef(&v, i, PARAMETER_W);
        let mut y_i = [0; PARAMETER_M];
        y_i.copy_from_slice(y_i_long.split_at(PARAMETER_M).0);
        for _ in 0..a {
            hasher.reset();
            hasher.input(&y_i);
            let mut y_i_long = [0; PARAMETER_N];
            hasher.result(&mut y_i_long);
            y_i.copy_from_slice(y_i_long.split_at(PARAMETER_M).0);
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
        z_i.copy_from_slice(z_i_long.split_at(PARAMETER_M).0);
        for _ in 0..a {
            inner_hasher.reset();
            inner_hasher.input(&z_i);
            let mut z_i_long = [0; PARAMETER_N];
            inner_hasher.result(&mut z_i_long);
            z_i.copy_from_slice(z_i_long.split_at(PARAMETER_M).0);
        }
        outer_hasher.input(&z_i);
    }

    let mut hash = [0; PARAMETER_N];
    outer_hasher.result(&mut hash);

    if hash == pubkey {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub mod util {
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
    let msg = util::deformat_bytes("0x48656c6c6f20776f726c64210a").unwrap();
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
    use super::util::*;

    // This is the OTS Private Key 0 defined in §B.2 Table 4
    const OTS_PRIVKEY_0: &str =
        "0xbfb757383fb08d324629115a84daf00b188d5695303c83c184e1ec7a501c431f7ce628fb82003a2829aab708432787d0fc735a29d671c7d790068b453dc8c9138174929461329d15068a4645a34412bd446d4c9e757463a7d5164efd50e05c93f283f3480df668de4daa74bb0e4c55315bc00f7d008bb6311e59a5bbca910fd7e62708eaf9c13801622563780302a0680ba9d39c078daa5ebc3160e1d80a1ea71f002efad2bfb4275e376af7138129e33e88cf7512ec1dcdc7df8d5270bc0fd78ed5a703e9200658d18bc4c05dd0ca8a356448a26f3f4fe4e0418b52bd6750a2c74e56d61450c5387e86ddad5a8121c88b1bc463e64f248a1f1d91d950957726629f18b6a2a4ea65fff4cf758b57333fe1d34af05b1cd7763696899c9869595f1741c31fdbb4864712f6b17fadc05d45926c831c7a755b7d7af57ac316ba6c2ae59a7b81490c5d1333a9cdd48b9cb36456821517a3a13cb7a8ed381d4d5f35453ba97fe8b2967dd74c8b10f31fc5f527a23b89c1266202a4d7c281e1f41fa020a262a9287cc979aaa59225d75df51b8257b92e780d1ab14c4ac3ecdac58f12809dfe0af1a3d9064338d96cb8eae88baa6a69265538873b4c17265fa9d573bcffde9c5c6a5c6a274eabe90ed2a8e6148c720196d237a839aaf5868af8da4d08295de81ec17090a82cb722f616362d380830f04841191e44f1f81b9880164b14cdc0d047000604105bad657d9fa2f9ef101cfd9490f4668b700d738f2fa9e1d11af45297ef310941e1e855f97968129bb173379193919f7b0fee9c037ae507c2d246ef43a877f023e5e66bbcd4f06b839f3bfb2b64de25cd67d1946b071198912946e2a599861bd9e8722ad1b55b8f0139305fcf8b6077d545d4488c4bcb652f29e1ad4d2d296971e4b0b7a57de305779e82319587b58d3ef4daeb08f630bd56847a07fa7aed97cb54ae420a0e6a58a15338110f7743cab8353371f8ca710a440940601f6c4b35362dd4948d5687b5cb6b5ec8b2ec59c2f06fd50f8919ebeaae92a061b0ba9f493c4991be5cd3a9d15360a9eb94f6f7adc28dddf174074f3df3c4cf1546a814ff16099cebf1fe0db1ace51c272fda9846fbb535815924b0077fa4cbb06f13155ce4e56c85a32661c901428b630a4c37ea5c7062156f07f6b3efff1181ee7fc03342415094e36191eb450a11cdea9c6f6cdc34de79cee0ba5bf230e9f1d429b343bb897881d2a19ef363cd1ab4117cbaad54dc292b74b8af9f5cf287f34b2551ef542f579fa65535c5036f80eb83be4c898266ffc531da2e1a91229b4b467852fe33a03a872572707342fdddeae64841225186babf353fa2a0cd0919d58cd240ab5c80be6ddf5f60d181592dca2be40118c1fdd46e0f14dffbcc7d5c9ad386547ba82939e49c9c74a8eccf1cea60aa327b5d2d0a66b1ca48912d6df49083e502400ffae9273c6de92a301e7bda1537cab085e5adfa9eb746e8eca94074e1812d69543ce3c1ce706f6e0b45f5f26f4ef39b34caa709335fd71e8fc01256612b0ca8398e97b247ae564b74b13839b3b1cf0a0dd8ba629a2c58355f84bab3989f00fd2c327bbfb35a218cc3ce49d6b34cbf8b6e8919e90c4eff400ca996b52a5d395a5615b73dae65586ac5c87f9dd3b9b3f82dbf509b5881f0643fa85d05ca4c644e1c41ccdaedbd2415d4f09b4a1b940b51fe823dff7617b8ee8304d96aab95ef6248e235d91d0f23b64727a6675adfc64efea72f6f8b4a47996c0dfd9c384d52d3ac27c4f4898fcc15e83ac182f97ea63f7d489283e2cc7e6ed180c86eaed6a9e3fbe5b262c1fa1f099f7c35ece71d9e467fab7a371dbcf400b544f462b3719a2ed8778155638ff814dbf42b107bb5246ee3dd82abf97787e6a69e014670912e3eb74936ebb64168b447e42522b57c2540ac4b49b9ae356c01eca62b411096e0ca16587830d3acd673e858863fedc4cea046587cba0556d2bf9884a73917c74730582e8e1815b8a07b18962ac05e500e045676be3f1495fcfa18caa4ab61e6962fe39a255dbf8a46d251100d127fab08db59512653607bda24302c9b910ca516413f376b9eba4b0d571b22253c2a9646131ac9a2af5f615f7322b8fc1b4ce627c77ad35a21ea9ded2cce91b3758a758224e35cf2918153a513d64cc1902d8e8c02d9442581d7e053a2798aa84d77a74b6e7f2cc5096d50646c890fb3f47e2e8e2dcdd890ea00934b9d8234830dbc4a30ac996b144f12b3e463c77f8188d1ecfc6ae6118911f2b9b3a6c7a1e5f909aa8b5c0aab8c69f1a7d436c307ca42d985974c7b870bc76494604eff492676c942c6cb7c75d4938805885dd054be58851ebe566057e1ee16b8c604a4734c373af622660b2a82357ac6effb4566c22d493f7a5642fceba2404dbefa8f956323fac87fac425f6de8d23c9e8b20ca1a76c1ffa467906173fd0245b0cd6639e6013ca79c4ed92426ee69ff5beeac0bbc6c0cb7808f379af1b7b7327436ad65c05458f2d0a6923c333e5129c4c99671fbb04488c3c088dc5e63d13e6a7010366109ca4c5f4b0a8d37780187e2e9930eaec10811569d4d72e3a1baf71a886b75eba6dc07ed027af0b2beffa71f9b43c8f5529be3b7a19212e8baa970d2420bf4123f678267f96c1c3ef26ab610cb0061172ba1ba0b701eeafe00692d1eb901818ccaefaeb8f799395da81711766d1f43fe1f8c15825208f3a21346b894b3d94e4f3aa29cbc194a7b2c8a810c4c5090422e81c66cc914ea1b0fa5942fe9780d548c0b330e3bf73f0cb0bda4bc9c9e6ff4fc3453aec5cc19a6a4bda4bc25931604704bf4386cd65780c6e73214c1da85ba4e8000c587dc917888e7e3d817672c0aef812788cc8579afa7e9b2e566309003ba667ca0e44a8601a0fde825d4d2cf1bb9cf467041e04af84c9d0cd9fd8dc7844965db75f81c8a596680753ce70a94c6156253bb426947de1d7662dd7e05e9a82c23cc3e5ca37dec279c506101a3d8d9f1e4f99b2a33741b59f8bddba7455419"
    ;
    // This is a concatencation of the values in §B.3 Table 10
    const EXPECTED_SIG_A: &str =
        "0xbfb757383fb08d324629115a84daf00b188d56954af079e885ddfd3245f29778d265e868a3bfeaa4fbad1928bfc57b22bcd949192452293d07d6b9adb98063e184b4cb949a51e1bb76d99d4249c0b448e62708eaf9c13801622563780302a0680ba9d39c39343cba3ffa6d75074ce89831b3f3436108318cfe08aa73607aec5664188a9dacdc34a295588c9ad3346382119552d1ceb92a78597a00c956372bf0f1dd245ec587c0a7a1b754cc327b27c839a6e46aa5f158adc1decaf0c1edc1a3a5d8958d726627b506d2990f62f22f0c943a418473678e3ffdbff482f3390b8d6e5229ae9c5d4c3f45e10455d8241a4922dd5f9d3c89180caa0f695203d8cf90f3c359be67999c4043f95de5f07d82b741347a3eb6ac0c25c4ffe472d48adeb37c7360da70711462013b7a4e5de81ec17090a82cb722f616362d380830f048412f892c824af65cc749f912a36dfa8ade2e4c3fd1b644393e8030924403b594fb5cacd8b2d28862e231b8d2908911dbbf5ba1f479a854808945d9e948a9a02269d24eb8fed6fb86101cbd0d8977219fb1e4aae6e6a9fe1b0d5099513f170c111dee95714dd79c16e7f2d4dd790e28bab0d562298c864e31e9c29678f0bb4744597e04156f532646c98a0b42e857b31d75743ff0f9bcf2db39d9b6224110b8d27b0a336d93aac081a2d849c612368b8cbb2fa9563a917be0c94770a7bb12713a4bae801fb3c1c4300291586feaadcf691b6cb07c16c8a2ed0884666e84dd4e4b720fb2517c4bc6f91ccb8725118e5770c6491f6ec665f54c4b3cffaa02ec594d31e6e26c0e4f5a082c9d9c9714701de0bf426e9f893484618c11f7017313f0c9549c5d415a8abc25243028514d6839a994fccb9cb76241d809146906a3d13f89f171cd1d9163d7cd563936837c61d97bb1a5337cc077c9034ffc0f9219841aa8e1edbfb62017ef9fd1ad9f6034017d35c338ac35778dd6c4c1abe4472a4a1c396b22e4f5cc2428045b36d13737c400751598cb57b779c5fd3f361cd5debc243303ae5baefd29857298f274d6bf595eadc89e5464ccf9608a6c95e35a26815a3ae9ad84a24464b174a29364da184afeb3b95b5b333759c0acdd96ce3f26314bb22b325a37ee5e349b22b13b54b24be5145344e7b8f34f772c93f56fd6958ce135f02847996c67e1f2efd4f6d91c577594060be328b013c9e9b0e8a2e5d8717e1a81c325cdccacb6e9fd9e92dd3e1bb84ae81dd363724ec66c090a1228dfa1cd3d9cc806f34664b4110476dd0beea78714c5ab71278818792cfae22290e740056a144af50f0b10962b5bcc18fc8234fd87046a183f4732a52bb7805ce207eebdafc5bd2fdc5e4e8d0ed7c48c1bad9c2f7793fc2c9303b3f47e2e8e2dcdd890ea00934b9d8234830dbc4acd29719c56cdb507030e6132132179e5807e1d3bf9edb9b301916217de0d746a0542316bebe9e8067a3801cbfe0cafed863d81210c1ec721eede49e55caba3ec960efa210f5f3e1c22c567ca475ef3ecf911b5d148e1b03fe6983c53411f76ea7877237906da2baa75c6ef752bf59f3812fa042ff81812092b29f5aa2f34af51a78a5fac586004f749c6e6dc55e033ababac0845cc9142e24f9ef0a641c51cbeb62d207bb700071fba8a68312ca204ce4d994c33551d5c00fad905bdb99c4f70ec7590a10d3ff8ca0d03b1845b5f8838d735142f185f9cf8f8d2db6c3b5d9e49e7ede41cd9aa5a09f72a0384fd4ff511a766b0278d14a9b7d32bf0307c0737a8ecf82ab1ca85296f354e6e3d2a96ab497c01e5ccd4530cf17bb29db7dd8aaaf1cd11487cea0d13730edb1df3547ef341b3cf3208753bb1b62d85a4e3fc2cffe0b890e1a99da4b2e0a9dde42f82f92d0946327cee"
    ;

    #[test]
    fn test_derive_pubkey() {
        let privkey = deformat_bytes(OTS_PRIVKEY_0).unwrap();
        let mut pubkey = [0; PUBKEY_SIZE];
        derive_pubkey(&privkey, &mut pubkey).unwrap();
        // This is OTS Public Key 0 in §B.2 Table 5
        assert_eq!("0x2db55a72075fcfab5aedbef77bf6b371dfb489d6e61ad2884a248345e6910618", format_bytes(&pubkey));
    }

    #[test]
    fn test_sign() {
        let privkey = deformat_bytes(OTS_PRIVKEY_0).unwrap();
        // This value is given in §B.3 Table 8
        let msg = deformat_bytes("0x48656c6c6f20776f726c64210a").unwrap();
        let mut sig = vec![0; SIG_SIZE];
        sign(&privkey, &msg, &mut sig).unwrap();
        assert_eq!(EXPECTED_SIG_A, format_bytes(&sig));
    }

    #[test]
    fn test_successful_verify() {
        let privkey = deformat_bytes(OTS_PRIVKEY_0).unwrap();
        let mut pubkey = [0; PUBKEY_SIZE];
        derive_pubkey(&privkey, &mut pubkey).unwrap();
        let msg = deformat_bytes("0x48656c6c6f20776f726c64210a").unwrap();
        let mut sig = vec![0; SIG_SIZE];
        sign(&privkey, &msg, &mut sig).unwrap();
        assert!(verify(&pubkey, &msg, &sig).unwrap());
    }
}
