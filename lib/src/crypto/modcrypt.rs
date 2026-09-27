use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};

/// Constant used by the DSi key scrambler to derive a normal key from a key X and key Y.
const KEY_SCRAMBLER_CONSTANT: u128 = 0xfffefb4e295902582a680f5f1a4f3e79;

/// AES-CTR cipher for modcrypt areas of DSi-enhanced and DSi-exclusive ROMs. The DSi AES engine treats keys, counters and
/// blocks as little-endian 128-bit numbers, so they are byte-reversed compared to standard AES.
pub struct Modcrypt {
    cipher: Aes128,
}

impl Modcrypt {
    /// Creates a new [`Modcrypt`] cipher for a retail ROM. The key is derived from the gamecode and the first 16 bytes of the
    /// SHA1-HMAC of the decrypted ARM9i program.
    pub fn new_retail(gamecode: [u8; 4], sha1_hmac_arm9i: &[u8; 0x14]) -> Self {
        let mut key_x = [0u8; 16];
        key_x[..8].copy_from_slice(b"Nintendo");
        key_x[8..12].copy_from_slice(&gamecode);
        for (dst, src) in key_x[12..].iter_mut().zip(gamecode.iter().rev()) {
            *dst = *src;
        }
        let mut key_y = [0u8; 16];
        key_y.copy_from_slice(&sha1_hmac_arm9i[..16]);

        let key = Self::scramble(u128::from_le_bytes(key_x), u128::from_le_bytes(key_y));
        Self { cipher: Aes128::new(&GenericArray::from(key.to_be_bytes())) }
    }

    fn scramble(key_x: u128, key_y: u128) -> u128 {
        (key_x ^ key_y).wrapping_add(KEY_SCRAMBLER_CONSTANT).rotate_left(42)
    }

    /// Encrypts or decrypts the given data in place. The initial counter is the first 16 bytes of the header SHA1-HMAC
    /// belonging to the modcrypt area: the ARM9 HMAC (with secure area) for area 1, the ARM7 HMAC for area 2.
    pub fn apply(&self, data: &mut [u8], sha1_hmac: &[u8; 0x14]) {
        let mut counter = [0u8; 16];
        counter.copy_from_slice(&sha1_hmac[..16]);
        let mut counter = u128::from_le_bytes(counter);

        for chunk in data.chunks_mut(16) {
            let mut block = GenericArray::from(counter.to_be_bytes());
            self.cipher.encrypt_block(&mut block);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= block[15 - i];
            }
            counter = counter.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_is_symmetric() {
        let modcrypt = Modcrypt::new_retail(*b"IREO", &[0x5a; 0x14]);
        let plain: Vec<u8> = (0..100u8).collect();
        let mut data = plain.clone();
        modcrypt.apply(&mut data, &[0xa5; 0x14]);
        assert_ne!(data, plain);
        modcrypt.apply(&mut data, &[0xa5; 0x14]);
        assert_eq!(data, plain);
    }
}
