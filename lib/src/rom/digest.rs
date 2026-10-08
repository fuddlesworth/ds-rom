use std::ops::Range;

use snafu::{Backtrace, Snafu};

use crate::crypto::hmac_sha1::HmacSha1;

/// Size of a SHA1-HMAC in the digest tables.
pub const DIGEST_HASH_SIZE: usize = 0x14;

/// A SHA1-HMAC in the digest tables.
pub type DigestHash = [u8; DIGEST_HASH_SIZE];

/// Shape of the digest tables, as given by the ROM header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestParams {
    /// Number of bytes covered by one sector hash, normally 0x400.
    pub sector_size: u32,
    /// Number of sector hashes covered by one block hash, normally 0x20.
    pub block_sector_count: u32,
}

/// Errors related to [`Digest::compute`].
#[derive(Debug, Snafu)]
pub enum DigestError {
    /// Occurs when a digest region is not a whole number of sectors.
    #[snafu(display(
        "digest region {start:#x}..{end:#x} is not a multiple of the sector size {sector_size:#x}:\n{backtrace}"
    ))]
    UnalignedRegion {
        /// Start of the region.
        start: u32,
        /// End of the region.
        end: u32,
        /// Sector size.
        sector_size: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when a digest region lies outside the ROM.
    #[snafu(display("digest region {start:#x}..{end:#x} exceeds the ROM size {rom_size:#x}:\n{backtrace}"))]
    RegionOutOfBounds {
        /// Start of the region.
        start: u32,
        /// End of the region.
        end: u32,
        /// Size of the ROM.
        rom_size: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when [`DigestParams`] has a zero sector size or block sector count.
    #[snafu(display("digest sector size and block sector count must both be nonzero:\n{backtrace}"))]
    ZeroSized {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when there are more replacement sector hashes than sectors.
    #[snafu(display(
        "{count} sector hashes were given to replace, but the digest regions have only {sectors} sectors:\n{backtrace}"
    ))]
    TooManyReplacedSectors {
        /// Number of replacement sector hashes.
        count: usize,
        /// Number of sectors in the digest regions.
        sectors: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// The digest tables of a DSi-enhanced or DSi-exclusive ROM. Every sector of the digest regions (the DS area and the DSi
/// area) gets a SHA1-HMAC in the sector hashtable, every [`DigestParams::block_sector_count`] entries of that table get one
/// in the block hashtable, and the whole block hashtable gets the master hash which is stored in the ROM header.
pub struct Digest {
    sector_hashtable: Vec<u8>,
    block_hashtable: Vec<u8>,
    master: DigestHash,
}

impl Digest {
    /// Computes the digest tables over the given regions of `rom`, in order.
    ///
    /// The digests cover the ROM in its *digest form*: with the ARM9 secure area encrypted and the modcrypt areas
    /// decrypted. Where `rom` differs from that form at the start of the first region, which is the case for a plaintext
    /// secure area, `first_sectors` gives the hashes of the first sectors instead of computing them from `rom`.
    ///
    /// # Errors
    ///
    /// This function will return an error if a region is out of bounds or not a whole number of sectors, if the parameters
    /// are zero, or if `first_sectors` has more hashes than there are sectors.
    pub fn compute(
        hmac_sha1: &HmacSha1,
        params: &DigestParams,
        rom: &[u8],
        regions: &[Range<u32>],
        first_sectors: &[DigestHash],
    ) -> Result<Self, DigestError> {
        if params.sector_size == 0 || params.block_sector_count == 0 {
            return ZeroSizedSnafu {}.fail();
        }

        // --------------------- Sector hashtable ---------------------
        let mut sector_hashes: Vec<DigestHash> = vec![];
        for region in regions {
            if region.is_empty() {
                continue;
            }
            if region.end as usize > rom.len() {
                return RegionOutOfBoundsSnafu { start: region.start, end: region.end, rom_size: rom.len() }.fail();
            }
            if !(region.end - region.start).is_multiple_of(params.sector_size) {
                return UnalignedRegionSnafu { start: region.start, end: region.end, sector_size: params.sector_size }.fail();
            }
            let sectors = rom[region.start as usize..region.end as usize].chunks(params.sector_size as usize);
            // Skip computing the sectors which are replaced below
            let skip = first_sectors.len().saturating_sub(sector_hashes.len());
            sector_hashes.extend(sectors.enumerate().map(|(i, sector)| {
                if i < skip {
                    [0; DIGEST_HASH_SIZE]
                } else {
                    hmac_sha1.compute(sector)
                }
            }));
        }
        if first_sectors.len() > sector_hashes.len() {
            return TooManyReplacedSectorsSnafu { count: first_sectors.len(), sectors: sector_hashes.len() }.fail();
        }
        sector_hashes[..first_sectors.len()].copy_from_slice(first_sectors);

        // The sector hashtable is padded with zeroed entries up to a whole number of blocks, and the last block hash covers
        // that padding
        let num_blocks = sector_hashes.len().div_ceil(params.block_sector_count as usize);
        sector_hashes.resize(num_blocks * params.block_sector_count as usize, [0; DIGEST_HASH_SIZE]);
        let sector_hashtable = sector_hashes.concat();

        // --------------------- Block hashtable ---------------------
        let block_size = params.block_sector_count as usize * DIGEST_HASH_SIZE;
        let block_hashtable =
            sector_hashtable.chunks(block_size).map(|block| hmac_sha1.compute(block)).collect::<Vec<_>>().concat();

        // --------------------- Master hash ---------------------
        let master = hmac_sha1.compute(&block_hashtable);

        Ok(Self { sector_hashtable, block_hashtable, master })
    }

    /// Returns the sector hashtable, one SHA1-HMAC per sector.
    pub fn sector_hashtable(&self) -> &[u8] {
        &self.sector_hashtable
    }

    /// Returns the block hashtable, one SHA1-HMAC per block of sector hashes.
    pub fn block_hashtable(&self) -> &[u8] {
        &self.block_hashtable
    }

    /// Returns the master hash, a SHA1-HMAC of the whole block hashtable.
    pub fn master(&self) -> &DigestHash {
        &self.master
    }
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    const PARAMS: DigestParams = DigestParams { sector_size: 0x10, block_sector_count: 2 };

    fn hmac() -> HmacSha1 {
        HmacSha1::new([0x5a; 64])
    }

    #[test]
    fn computes_tables() {
        let hmac = hmac();
        let rom = (0..0x80).map(|i| i as u8).collect::<Vec<_>>();
        let digest = Digest::compute(&hmac, &PARAMS, &rom, &[0x10..0x30, 0x50..0x60], &[]).unwrap();

        // Three sectors, padded to two blocks
        let sectors = [hmac.compute(&rom[0x10..0x20]), hmac.compute(&rom[0x20..0x30]), hmac.compute(&rom[0x50..0x60])];
        let mut sector_hashtable = sectors.concat();
        sector_hashtable.resize(4 * DIGEST_HASH_SIZE, 0);
        assert_eq!(digest.sector_hashtable(), sector_hashtable);

        let block_hashtable = [hmac.compute(&sector_hashtable[..0x28]), hmac.compute(&sector_hashtable[0x28..])].concat();
        assert_eq!(digest.block_hashtable(), block_hashtable);
        assert_eq!(digest.master(), &hmac.compute(&block_hashtable));
    }

    #[test]
    fn replaces_first_sectors() {
        let hmac = hmac();
        let rom = vec![0u8; 0x40];
        let replaced = [[1; DIGEST_HASH_SIZE]];
        let digest = Digest::compute(&hmac, &PARAMS, &rom, &[0..0x20], &replaced).unwrap();
        assert_eq!(&digest.sector_hashtable()[..DIGEST_HASH_SIZE], &replaced[0]);
        assert_eq!(&digest.sector_hashtable()[DIGEST_HASH_SIZE..], &hmac.compute(&rom[0x10..0x20]));

        let error = Digest::compute(&hmac, &PARAMS, &rom, &[0..0x10], &[[1; DIGEST_HASH_SIZE]; 2]).err().unwrap();
        assert!(matches!(error, DigestError::TooManyReplacedSectors { .. }));
    }

    #[test]
    fn rejects_bad_regions() {
        let hmac = hmac();
        let rom = vec![0u8; 0x40];
        let error = Digest::compute(&hmac, &PARAMS, &rom, &[0..0x18], &[]).err().unwrap();
        assert!(matches!(error, DigestError::UnalignedRegion { .. }));
        let error = Digest::compute(&hmac, &PARAMS, &rom, &[0x30..0x50], &[]).err().unwrap();
        assert!(matches!(error, DigestError::RegionOutOfBounds { .. }));
        let params = DigestParams { sector_size: 0, ..PARAMS };
        let error = Digest::compute(&hmac, &params, &rom, &[0..0x10], &[]).err().unwrap();
        assert!(matches!(error, DigestError::ZeroSized { .. }));
    }
}
