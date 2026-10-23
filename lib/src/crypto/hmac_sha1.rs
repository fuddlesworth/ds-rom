use std::backtrace::Backtrace;

use sha1::{Digest, Sha1};
use snafu::Snafu;

/// Performs HMAC-SHA1 hashing to generate signatures.
#[derive(Clone)]
pub struct HmacSha1 {
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
}

impl HmacSha1 {
    /// Creates a new [`HmacSha1`] instance with the given key.
    pub fn new(key: [u8; 64]) -> Self {
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        inner_pad.iter_mut().zip(key.iter()).for_each(|(i, k)| *i ^= *k);
        outer_pad.iter_mut().zip(key.iter()).for_each(|(o, k)| *o ^= *k);
        Self { inner_pad, outer_pad }
    }

    /// Computes the HMAC-SHA1 hash of the given data using the key.
    pub fn compute(&self, data: &[u8]) -> [u8; 20] {
        let mut sha1 = Sha1::new();
        sha1.update(self.inner_pad);
        sha1.update(data);
        let inner_hash = sha1.finalize_reset();

        sha1.update(self.outer_pad);
        sha1.update(inner_hash);
        let outer_hash = sha1.finalize();

        outer_hash.into()
    }

    /// Computes the HMAC-SHA1 hash of the given data with [`sha1_masked`] in place of SHA-1, as NitroSDK signs an
    /// overlay table.
    pub fn compute_masked(&self, data: &[u8]) -> [u8; 20] {
        let mut inner = Vec::with_capacity(self.inner_pad.len() + data.len());
        inner.extend_from_slice(&self.inner_pad);
        inner.extend_from_slice(data);
        let inner_hash = sha1_masked(&inner);

        let mut outer = Vec::with_capacity(self.outer_pad.len() + inner_hash.len());
        outer.extend_from_slice(&self.outer_pad);
        outer.extend_from_slice(&inner_hash);
        sha1_masked(&outer)
    }
}

/// SHA-1 with words 6 and 14 of every 64-byte block cleared before the block is compressed. NitroSDK's digest of an
/// overlay table is computed this way (`FSi_CompareDigest`'s masked mode): it leaves out the file ID of each 32-byte
/// overlay entry, which the ROM tool assigns after the table is signed.
pub fn sha1_masked(message: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((message.len() as u64) * 8).to_be_bytes());

    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        w[6] = 0;
        w[14] = 0;
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a827999),
                20..40 => (b ^ c ^ d, 0x6ed9eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }

    let mut hash = [0; 20];
    for (out, word) in hash.chunks_exact_mut(4).zip(state) {
        out.copy_from_slice(&word.to_be_bytes());
    }
    hash
}

/// Errors related to parsing a HMAC-SHA1 key from bytes.
#[derive(Debug, Snafu)]
pub enum HmacSha1FromBytesError {
    /// Occurs when the key is not 64 bytes long.
    #[snafu(display("key must be 64 bytes long, but got {} bytes:\n{backtrace}", length))]
    InvalidKeyLength {
        /// Actual key length.
        length: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl TryFrom<&[u8]> for HmacSha1 {
    type Error = HmacSha1FromBytesError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            return InvalidKeyLengthSnafu { length: value.len() }.fail();
        }
        let mut key = [0; 64];
        key.copy_from_slice(value);
        Ok(Self::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn masked_sha1_clears_words_6_and_14() {
        // The empty message's only block has zeros in those words, so it hashes as plain SHA-1
        assert_eq!(hex(&sha1_masked(&[])), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let message: Vec<u8> = (0..200).collect();
        assert_eq!(hex(&sha1_masked(&message)), "a60d522c66fc63d6ab05f0e26eea0dfbf78ed1a5");
    }

    #[test]
    fn masked_hmac_sha1() {
        let key: Vec<u8> = (0..64).collect();
        let data: Vec<u8> = (0..96).collect();
        let hmac = HmacSha1::try_from(key.as_slice()).unwrap();
        assert_eq!(hex(&hmac.compute_masked(&data)), "f3f8a59ab3492be51159047c5d376c8234599ab5");
    }
}
