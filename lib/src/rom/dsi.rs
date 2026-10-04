use std::{borrow::Cow, io, mem::size_of, ops::Range};

use bytemuck::{Pod, Zeroable};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use snafu::{Backtrace, Snafu};

use super::{
    Arm9, Autoload,
    raw::{self, AutoloadInfo, AutoloadKind, ProgramOffset, RawHeaderError, TableOffset, TwlAutoloadInfoEntry},
};
use crate::{
    compress::lz77::{Lz77, Lz77DecompressError},
    crypto::{blowfish::BlowfishKey, hmac_sha1::HmacSha1, modcrypt::Modcrypt},
};

/// Marks the end of [`LtdModuleParams`].
const LTD_NITROCODE: u32 = 0xdec01463;
/// The ARM9 program is compressed from this offset, so [`LtdModuleParams`] must be stored before it.
const ARM9_COMPRESSION_START: u32 = 0x4000;
const LZ77: Lz77 = Lz77 {};

/// Size of the part of the ARM9 secure area which is encrypted on the cartridge.
const SECURE_AREA_ENCRYPTED_SIZE: u32 = 0x800;
/// Size of the part of the ARM9 program which is considered the secure area by the header SHA1-HMACs.
const SECURE_AREA_SIZE: usize = 0x4000;
/// Alignment of the digest hashtables and the end of the DS area, as observed in retail ROMs.
const DSI_TABLE_ALIGNMENT: u32 = 0x200;
/// The DSi region starts at a multiple of this alignment.
const DSI_REGION_ALIGNMENT: u32 = 0x80000;
/// Size of a SHA1 digest.
const DIGEST_SIZE: usize = 0x14;

type Digest = [u8; DIGEST_SIZE];

/// DSi-specific parts of a DSi-enhanced or DSi-exclusive ROM. The ARM9i and ARM7i programs are stored decrypted.
#[derive(Clone)]
pub struct Dsi<'a> {
    arm9i: Cow<'a, [u8]>,
    ltd: Option<Ltd<'a>>,
    arm7i: Cow<'a, [u8]>,
    region_prefix: Cow<'a, [u8]>,
    config: DsiConfig,
}

/// The ARM9i program split into its parts. The ARM9i program holds the LTD ("limited") module, which is autoloaded
/// only in DSi mode.
#[derive(Clone)]
pub struct Ltd<'a> {
    static_data: Cow<'a, [u8]>,
    autoloads: Vec<Autoload<'a>>,
}

/// Parameters of the LTD module, stored in the ARM9 program at the header's ARM9i build info offset.
#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Debug, PartialEq, Eq)]
pub struct LtdModuleParams {
    /// Address of the autoload list.
    pub autoload_list_start: u32,
    /// End address of the autoload list.
    pub autoload_list_end: u32,
    /// Address of the first autoload block.
    pub autoload_start: u32,
    /// End address of the compressed ARM9i program, or zero if it is not compressed.
    pub compressed_static_end: u32,
    nitrocode: u32,
    nitrocode_rev: u32,
}

/// Configuration of the LTD module, see [`Ltd`].
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct LtdConfig {
    /// Whether the ARM9i program is compressed.
    pub compressed: bool,
}

/// Configuration of the DSi-specific parts of a ROM, see [`Dsi`].
#[derive(Serialize, Deserialize, Clone)]
pub struct DsiConfig {
    /// ARM9i program.
    pub arm9i: DsiProgram,
    /// ARM7i program.
    pub arm7i: DsiProgram,
    /// Number of bytes hashed by each sector digest.
    pub digest_sector_size: u32,
    /// Number of sector digests hashed by each block digest.
    pub digest_sector_count: u32,
    /// Values derived from the encrypted secure area. See [`SecureAreaValues`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_area: Option<SecureAreaValues>,
    /// Present if the ARM9i program is split into the parts of its LTD module, see [`Ltd`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ltd: Option<LtdConfig>,
}

/// A DSi-specific program, ARM9i or ARM7i.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct DsiProgram {
    /// Base address.
    pub base_address: u32,
    /// Raw value of the entry field in the header. The ARM7i uses this field for something else.
    pub entry: u32,
    /// Build info offset, relative to the start of the program.
    pub build_info: u32,
    /// Number of bytes at the start of the program which are encrypted with modcrypt.
    pub modcrypt_size: u32,
}

/// Values derived from the encrypted ARM9 secure area. Dumps store the secure area decrypted, and encrypting it requires the
/// Blowfish key from the ARM7 BIOS. These values allow building without the key, as long as the secure area is unchanged.
#[derive(Serialize, Deserialize, Clone)]
pub struct SecureAreaValues {
    /// CRC checksum of the encrypted secure area.
    pub crc: u16,
    /// SHA1-HMAC of the ARM9 program with the encrypted secure area.
    #[serde(with = "hex_digest")]
    pub sha1_hmac_arm9_with_secure_area: Digest,
    /// Digests of the sectors which overlap the encrypted secure area.
    #[serde(with = "hex_digests")]
    pub sector_digests: Vec<Digest>,
}

/// Errors related to [`Dsi`].
#[derive(Debug, Snafu)]
pub enum DsiError {
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// Occurs when a modcrypt area does not start at its program, which is not supported yet.
    #[snafu(display(
        "modcrypt area {area} at {offset:#x} does not start at the {program} program at {program_offset:#x}:\n{backtrace}"
    ))]
    UnsupportedModcryptArea {
        /// Modcrypt area number, 1 or 2.
        area: u32,
        /// Offset to the modcrypt area.
        offset: u32,
        /// Program name.
        program: &'static str,
        /// Offset to the program.
        program_offset: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the ROM uses debug modcrypt keys, which are not supported yet.
    #[snafu(display("DSi titles with debug modcrypt keys are not supported:\n{backtrace}"))]
    DebugModcrypt {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when building without a HMAC-SHA1 key, which is needed for the digests.
    #[snafu(display("the ARM9 HMAC-SHA1 key is needed to build DSi ROMs:\n{backtrace}"))]
    NoHmacSha1Key {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when building with an unencrypted secure area, without a Blowfish key or stored secure area values.
    #[snafu(display(
        "the secure area is unencrypted, so a Blowfish key or secure area values are needed to build the digests:\n{backtrace}"
    ))]
    NoSecureAreaValues {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
    },
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// Occurs when the stored secure area digests don't cover the secure area.
    #[snafu(display("expected {expected} secure area sector digests but got {actual}:\n{backtrace}"))]
    WrongSecureAreaDigestCount {
        /// Expected amount.
        expected: usize,
        /// Actual amount.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

/// Layout of the DSi-specific parts of a built ROM, see [`Dsi::layout`].
#[derive(Clone, Copy, Default)]
pub struct DsiLayout {
    /// Area covered by the DS sector digests.
    pub digest_ds_area: TableOffset,
    /// Area covered by the DSi sector digests.
    pub digest_dsi_area: TableOffset,
    /// Sector digest hashtable.
    pub digest_sector_hashtable: TableOffset,
    /// Block digest hashtable.
    pub digest_block_hashtable: TableOffset,
    /// End of the DS area, excluding the DSi region.
    pub rom_size_ds: u32,
    /// Start of the DSi region.
    pub dsi_region_start: u32,
    /// ARM9i program.
    pub arm9i: ProgramOffset,
    /// ARM7i program.
    pub arm7i: ProgramOffset,
    /// End of the DSi area.
    pub rom_size_dsi: u32,
}

/// Header values computed by [`Dsi::finalize`].
#[derive(Clone, Copy, Default)]
pub struct DsiHeaderValues {
    /// Layout of the DSi-specific parts.
    pub layout: DsiLayout,
    /// CRC checksum of the encrypted secure area, if known.
    pub secure_area_crc: Option<u16>,
    /// SHA1-HMAC of the ARM9 program with the encrypted secure area.
    pub sha1_hmac_arm9_with_secure_area: Digest,
    /// SHA1-HMAC of the ARM7 program.
    pub sha1_hmac_arm7: Digest,
    /// SHA1-HMAC of the block digest hashtable.
    pub sha1_hmac_digest: Digest,
    /// SHA1-HMAC of the banner.
    pub sha1_hmac_banner: Digest,
    /// SHA1-HMAC of the decrypted ARM9i program.
    pub sha1_hmac_arm9i: Digest,
    /// SHA1-HMAC of the decrypted ARM7i program.
    pub sha1_hmac_arm7i: Digest,
    /// SHA1-HMAC of the ARM9 program excluding the secure area.
    pub sha1_hmac_arm9: Digest,
    /// Modcrypt area 1, covering the ARM9i program.
    pub modcrypt_area_1: TableOffset,
    /// Modcrypt area 2, covering the ARM7i program.
    pub modcrypt_area_2: TableOffset,
}

impl<'a> Dsi<'a> {
    /// Creates a new [`Dsi`] from decrypted programs.
    pub fn new<T: Into<Cow<'a, [u8]>>>(arm9i: T, arm7i: T, region_prefix: T, config: DsiConfig) -> Self {
        Self { arm9i: arm9i.into(), ltd: None, arm7i: arm7i.into(), region_prefix: region_prefix.into(), config }
    }

    /// Creates a new [`Dsi`] from the parts of the ARM9i program's LTD module. Returns the LTD module parameters to write
    /// into the ARM9 program with [`Arm9::write_ltd_params`].
    ///
    /// # Errors
    ///
    /// This function will return an error if compressing the ARM9i program fails.
    pub fn with_ltd<T: Into<Cow<'a, [u8]>>>(
        ltd: Ltd<'a>,
        arm7i: T,
        region_prefix: T,
        config: DsiConfig,
    ) -> Result<(Self, LtdModuleParams), DsiError> {
        let base = config.arm9i.base_address;
        let compressed = config.ltd.is_some_and(|ltd| ltd.compressed);

        let mut image = ltd.static_data.to_vec();
        let autoload_start = base + image.len() as u32;
        for autoload in &ltd.autoloads {
            image.extend(autoload.full_data());
        }
        let autoload_list_start = base + image.len() as u32;
        for autoload in &ltd.autoloads {
            image.extend(autoload.info().entry_bytes());
        }
        let autoload_list_end = base + image.len() as u32;

        let arm9i = if compressed { LZ77.compress(&image, 0)?.into_vec() } else { image };
        let params = LtdModuleParams {
            autoload_list_start,
            autoload_list_end,
            autoload_start,
            compressed_static_end: if compressed { base + arm9i.len() as u32 } else { 0 },
            nitrocode: LTD_NITROCODE,
            nitrocode_rev: LTD_NITROCODE.swap_bytes(),
        };
        let dsi =
            Self { arm9i: arm9i.into(), ltd: Some(ltd), arm7i: arm7i.into(), region_prefix: region_prefix.into(), config };
        Ok((dsi, params))
    }

    /// Extracts the DSi-specific parts of a raw ROM, or returns `None` if the ROM is not DSi-enhanced or DSi-exclusive.
    ///
    /// # Errors
    ///
    /// This function will return an error if the header is invalid or the ROM uses unsupported modcrypt features.
    pub fn extract(rom: &raw::Rom) -> Result<Option<Self>, DsiError> {
        let header = rom.header()?;
        if !header.is_dsi() {
            return Ok(None);
        }
        if header.uses_modcrypt_debug_key() {
            return DebugModcryptSnafu {}.fail();
        }

        let data = rom.data();
        let mut arm9i = data[program_range(&header.arm9i)].to_vec();
        let mut arm7i = data[program_range(&header.arm7i)].to_vec();

        let modcrypt = Modcrypt::new_retail(header.gamecode.0, &header.sha1_hmac_arm9i);
        let arm9i_modcrypt_size = modcrypt_size(1, &header.modcrypt_area_1, "ARM9i", &header.arm9i, &mut arm9i, |data| {
            modcrypt.apply(data, &header.sha1_hmac_arm9_with_secure_area)
        })?;
        let arm7i_modcrypt_size = modcrypt_size(2, &header.modcrypt_area_2, "ARM7i", &header.arm7i, &mut arm7i, |data| {
            modcrypt.apply(data, &header.sha1_hmac_arm7)
        })?;

        // The digest tables start with the DS area, so the first sectors belong to the secure area
        let sector_size = header.digest_sector_size;
        let num_secure_sectors = SECURE_AREA_ENCRYPTED_SIZE.div_ceil(sector_size) as usize;
        let sector_table = &data[table_range(&header.digest_sector_hashtable)];
        let sector_digests = sector_table.as_chunks::<DIGEST_SIZE>().0.iter().take(num_secure_sectors).copied().collect();

        let dsi_region_start = header.dsi_rom_region_end as usize * DSI_REGION_ALIGNMENT as usize;
        let region_prefix = data[dsi_region_start..header.arm9i.offset as usize].to_vec();

        // The LTD module parameters are stored before the compressed part of the ARM9 program, so they can be read as-is
        let ltd_params = (header.arm9i_build_info_offset < ARM9_COMPRESSION_START)
            .then(|| LtdModuleParams::from_arm9(&data[program_range(&header.arm9)], header.arm9i_build_info_offset))
            .flatten();
        let ltd = match ltd_params {
            Some(params) => Ltd::split(&arm9i, header.arm9i.base_addr, &params)?,
            None => None,
        };

        let config = DsiConfig {
            arm9i: DsiProgram {
                base_address: header.arm9i.base_addr,
                entry: header.arm9i.entry,
                build_info: header.arm9i_build_info_offset,
                modcrypt_size: arm9i_modcrypt_size,
            },
            arm7i: DsiProgram {
                base_address: header.arm7i.base_addr,
                entry: header.arm7i.entry,
                build_info: header.arm7i_build_info_offset,
                modcrypt_size: arm7i_modcrypt_size,
            },
            digest_sector_size: sector_size,
            digest_sector_count: header.digest_sector_count,
            secure_area: Some(SecureAreaValues {
                crc: header.secure_area_crc,
                sha1_hmac_arm9_with_secure_area: header.sha1_hmac_arm9_with_secure_area,
                sector_digests,
            }),
            ltd: ltd.as_ref().map(|_| LtdConfig { compressed: ltd_params.is_some_and(|p| p.compressed_static_end != 0) }),
        };

        let mut dsi = Self::new(arm9i, arm7i, region_prefix, config);
        dsi.ltd = ltd;
        Ok(Some(dsi))
    }

    /// Returns the parts of the ARM9i program, if it was split into its LTD module.
    pub fn ltd(&self) -> Option<&Ltd<'a>> {
        self.ltd.as_ref()
    }

    /// Returns the decrypted ARM9i program.
    pub fn arm9i(&self) -> &[u8] {
        &self.arm9i
    }

    /// Returns the decrypted ARM7i program.
    pub fn arm7i(&self) -> &[u8] {
        &self.arm7i
    }

    /// Returns the data between the start of the DSi region and the ARM9i program.
    pub fn region_prefix(&self) -> &[u8] {
        &self.region_prefix
    }

    /// Returns the config.
    pub fn config(&self) -> &DsiConfig {
        &self.config
    }

    /// Computes the layout of the DSi-specific parts, given the end of the DS area. The DS area must end at a multiple of
    /// the digest sector size.
    pub fn layout(&self, arm9_offset: u32, ds_area_end: u32) -> DsiLayout {
        let sector_size = self.config.digest_sector_size;
        let digest_ds_area = TableOffset { offset: arm9_offset, size: ds_area_end - arm9_offset };
        let dsi_area_size =
            (self.arm9i.len() as u32).next_multiple_of(sector_size) + (self.arm7i.len() as u32).next_multiple_of(sector_size);

        let num_sectors = (digest_ds_area.size + dsi_area_size) / sector_size;
        let num_blocks = num_sectors.div_ceil(self.config.digest_sector_count);
        let digest_sector_hashtable =
            TableOffset { offset: ds_area_end, size: num_blocks * self.config.digest_sector_count * DIGEST_SIZE as u32 };
        let digest_block_hashtable = TableOffset {
            offset: (digest_sector_hashtable.offset + digest_sector_hashtable.size).next_multiple_of(DSI_TABLE_ALIGNMENT),
            size: num_blocks * DIGEST_SIZE as u32,
        };
        let rom_size_ds = (digest_block_hashtable.offset + digest_block_hashtable.size).next_multiple_of(DSI_TABLE_ALIGNMENT);

        let dsi_region_start = rom_size_ds.next_multiple_of(DSI_REGION_ALIGNMENT);
        let arm9i_offset = dsi_region_start + self.region_prefix.len() as u32;
        let arm7i_offset = (arm9i_offset + self.arm9i.len() as u32).next_multiple_of(sector_size);
        let rom_size_dsi = (arm7i_offset + self.arm7i.len() as u32).next_multiple_of(sector_size);

        DsiLayout {
            digest_ds_area,
            digest_dsi_area: TableOffset { offset: arm9i_offset, size: rom_size_dsi - arm9i_offset },
            digest_sector_hashtable,
            digest_block_hashtable,
            rom_size_ds,
            dsi_region_start,
            arm9i: ProgramOffset {
                offset: arm9i_offset,
                entry: self.config.arm9i.entry,
                base_addr: self.config.arm9i.base_address,
                size: self.arm9i.len() as u32,
            },
            arm7i: ProgramOffset {
                offset: arm7i_offset,
                entry: self.config.arm7i.entry,
                base_addr: self.config.arm7i.base_address,
                size: self.arm7i.len() as u32,
            },
            rom_size_dsi,
        }
    }

    /// Computes the digest hashtables and SHA1-HMACs, and writes the hashtables and the encrypted ARM9i and ARM7i programs
    /// to `rom`. The DSi-specific parts must already be written to `rom` in plaintext according to `layout`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the HMAC-SHA1 key is missing, or if the secure area values are needed but
    /// missing.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        &self,
        rom: &mut [u8],
        layout: DsiLayout,
        arm9: &Arm9,
        arm9_offset: u32,
        arm7: TableOffset,
        banner: TableOffset,
        gamecode: [u8; 4],
        hmac_sha1: Option<&HmacSha1>,
        blowfish_key: Option<&BlowfishKey>,
    ) -> Result<DsiHeaderValues, DsiError> {
        let Some(hmac_sha1) = hmac_sha1 else {
            return NoHmacSha1KeySnafu {}.fail();
        };
        let sector_size = self.config.digest_sector_size as usize;

        // The secure area is hashed in its encrypted form
        let arm9_data = arm9.full_data();
        let encrypted_secure_area = if arm9.is_encrypted() {
            None
        } else if let Some(key) = blowfish_key {
            Some(arm9.encrypted_secure_area(key, u32::from_le_bytes(gamecode)))
        } else if self.config.secure_area.is_none() {
            return NoSecureAreaValuesSnafu {}.fail();
        } else {
            None
        };
        let stored_secure_area = if arm9.is_encrypted() || encrypted_secure_area.is_some() {
            None
        } else {
            self.config.secure_area.as_ref()
        };

        // --------------------- Sector digests ---------------------
        let mut sector_digests: Vec<Digest> = Vec::with_capacity(layout.digest_sector_hashtable.size as usize / DIGEST_SIZE);
        for sector in rom[table_range(&layout.digest_ds_area)].chunks(sector_size) {
            sector_digests.push(hmac_sha1.compute(sector));
        }
        let num_secure_sectors = SECURE_AREA_ENCRYPTED_SIZE.div_ceil(self.config.digest_sector_size) as usize;
        if let Some(secure_area) = &encrypted_secure_area {
            // The secure area is at the start of the DS area, see `layout`
            let mut sectors = rom[arm9_offset as usize..arm9_offset as usize + num_secure_sectors * sector_size].to_vec();
            sectors[..SECURE_AREA_ENCRYPTED_SIZE as usize]
                .copy_from_slice(&secure_area[..SECURE_AREA_ENCRYPTED_SIZE as usize]);
            for (digest, sector) in sector_digests.iter_mut().zip(sectors.chunks(sector_size)) {
                *digest = hmac_sha1.compute(sector);
            }
        } else if let Some(secure_area) = stored_secure_area {
            if secure_area.sector_digests.len() != num_secure_sectors {
                return WrongSecureAreaDigestCountSnafu {
                    expected: num_secure_sectors,
                    actual: secure_area.sector_digests.len(),
                }
                .fail();
            }
            sector_digests[..num_secure_sectors].copy_from_slice(&secure_area.sector_digests);
        }
        for sector in rom[table_range(&layout.digest_dsi_area)].chunks(sector_size) {
            sector_digests.push(hmac_sha1.compute(sector));
        }
        sector_digests.resize(layout.digest_sector_hashtable.size as usize / DIGEST_SIZE, [0; DIGEST_SIZE]);
        let sector_hashtable = sector_digests.concat();

        // --------------------- Block digests ---------------------
        let block_size = self.config.digest_sector_count as usize * DIGEST_SIZE;
        let block_hashtable =
            sector_hashtable.chunks(block_size).map(|block| hmac_sha1.compute(block)).collect::<Vec<_>>().concat();

        rom[table_range(&layout.digest_sector_hashtable)].copy_from_slice(&sector_hashtable);
        rom[table_range(&layout.digest_block_hashtable)].copy_from_slice(&block_hashtable);

        // --------------------- SHA1-HMACs ---------------------
        let (secure_area_crc, sha1_hmac_arm9_with_secure_area) = if let Some(secure_area) = &encrypted_secure_area {
            let mut data = arm9_data.to_vec();
            data[..SECURE_AREA_SIZE].copy_from_slice(secure_area);
            (None, hmac_sha1.compute(&data))
        } else if let Some(secure_area) = stored_secure_area {
            (Some(secure_area.crc), secure_area.sha1_hmac_arm9_with_secure_area)
        } else {
            (None, hmac_sha1.compute(arm9_data))
        };
        let sha1_hmac_arm9i = hmac_sha1.compute(&self.arm9i);
        let sha1_hmac_arm7 = hmac_sha1.compute(&rom[table_range(&arm7)]);

        // --------------------- Modcrypt ---------------------
        let modcrypt = Modcrypt::new_retail(gamecode, &sha1_hmac_arm9i);
        let modcrypt_area_1 = modcrypt_area(&layout.arm9i, self.config.arm9i.modcrypt_size);
        let modcrypt_area_2 = modcrypt_area(&layout.arm7i, self.config.arm7i.modcrypt_size);
        modcrypt.apply(&mut rom[table_range(&modcrypt_area_1)], &sha1_hmac_arm9_with_secure_area);
        modcrypt.apply(&mut rom[table_range(&modcrypt_area_2)], &sha1_hmac_arm7);

        Ok(DsiHeaderValues {
            layout,
            secure_area_crc,
            sha1_hmac_arm9_with_secure_area,
            sha1_hmac_arm7,
            sha1_hmac_digest: hmac_sha1.compute(&block_hashtable),
            sha1_hmac_banner: hmac_sha1.compute(&rom[table_range(&banner)]),
            sha1_hmac_arm9i,
            sha1_hmac_arm7i: hmac_sha1.compute(&self.arm7i),
            sha1_hmac_arm9: hmac_sha1.compute(&arm9_data[SECURE_AREA_SIZE.min(arm9_data.len())..]),
            modcrypt_area_1,
            modcrypt_area_2,
        })
    }
}

impl<'a> Ltd<'a> {
    /// Creates a new [`Ltd`] from the decompressed data before the autoload blocks, and the autoload blocks.
    pub fn new<T: Into<Cow<'a, [u8]>>>(static_data: T, autoloads: Vec<Autoload<'a>>) -> Self {
        Self { static_data: static_data.into(), autoloads }
    }

    /// Splits an ARM9i program into its parts. Returns `None` if the program does not have the expected layout.
    fn split(arm9i: &[u8], base: u32, params: &LtdModuleParams) -> Result<Option<Self>, DsiError> {
        let image = if params.compressed_static_end != 0 {
            LZ77.decompress(arm9i)?.into_vec()
        } else {
            arm9i.to_vec()
        };
        let offset_of = |address: u32| address.checked_sub(base).map(|offset| offset as usize);
        let (Some(autoload_start), Some(list_start), Some(list_end)) =
            (offset_of(params.autoload_start), offset_of(params.autoload_list_start), offset_of(params.autoload_list_end))
        else {
            return Ok(None);
        };
        if list_end != image.len() || list_start > list_end || autoload_start > list_start {
            return Ok(None);
        }

        let mut autoloads = vec![];
        let mut offset = autoload_start;
        let entries = image[list_start..list_end].chunks_exact(size_of::<TwlAutoloadInfoEntry>());
        for (index, entry) in entries.enumerate() {
            let entry: TwlAutoloadInfoEntry = bytemuck::pod_read_unaligned(entry);
            let mut info = AutoloadInfo::new_twl(entry, index as u32);
            info.kind = AutoloadKind::Ltd(index as u32);
            let end = offset + entry.code_size as usize;
            if end > list_start {
                return Ok(None);
            }
            autoloads.push(Autoload::new(image[offset..end].to_vec(), info));
            offset = end;
        }
        if offset != list_start {
            return Ok(None);
        }

        Ok(Some(Self { static_data: image[..autoload_start].to_vec().into(), autoloads }))
    }

    /// Returns the decompressed data before the autoload blocks.
    pub fn static_data(&self) -> &[u8] {
        &self.static_data
    }

    /// Returns the autoload blocks.
    pub fn autoloads(&self) -> &[Autoload<'a>] {
        &self.autoloads
    }
}

impl LtdModuleParams {
    /// Reads the parameters from an ARM9 program, or returns `None` if they are not at the given offset.
    fn from_arm9(arm9: &[u8], offset: u32) -> Option<Self> {
        let offset = offset as usize;
        let params: Self = bytemuck::pod_read_unaligned(arm9.get(offset..offset + size_of::<Self>())?);
        (params.nitrocode == LTD_NITROCODE && params.nitrocode_rev == LTD_NITROCODE.swap_bytes()).then_some(params)
    }
}

fn program_range(program: &ProgramOffset) -> Range<usize> {
    program.offset as usize..(program.offset + program.size) as usize
}

fn table_range(table: &TableOffset) -> Range<usize> {
    table.offset as usize..(table.offset + table.size) as usize
}

fn modcrypt_area(program: &ProgramOffset, size: u32) -> TableOffset {
    if size == 0 {
        TableOffset::default()
    } else {
        TableOffset { offset: program.offset, size }
    }
}

/// Decrypts the modcrypt area of a program and returns the number of bytes it covers.
fn modcrypt_size(
    area: u32,
    modcrypt_area: &TableOffset,
    program: &'static str,
    program_offset: &ProgramOffset,
    data: &mut [u8],
    decrypt: impl FnOnce(&mut [u8]),
) -> Result<u32, DsiError> {
    if modcrypt_area.size == 0 {
        return Ok(0);
    }
    if modcrypt_area.offset != program_offset.offset || modcrypt_area.size > program_offset.size {
        return UnsupportedModcryptAreaSnafu {
            area,
            offset: modcrypt_area.offset,
            program,
            program_offset: program_offset.offset,
        }
        .fail();
    }
    decrypt(&mut data[..modcrypt_area.size as usize]);
    Ok(modcrypt_area.size)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(string: &str) -> Result<Digest, String> {
    if string.len() != DIGEST_SIZE * 2 {
        return Err(format!("expected {} hex digits but got {}", DIGEST_SIZE * 2, string.len()));
    }
    let mut digest = [0; DIGEST_SIZE];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&string[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(digest)
}

mod hex_digest {
    use super::*;

    pub fn serialize<S: Serializer>(digest: &Digest, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&to_hex(digest))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Digest, D::Error> {
        from_hex(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

mod hex_digests {
    use super::*;

    pub fn serialize<S: Serializer>(digests: &[Digest], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(digests.iter().map(|digest| to_hex(digest)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Digest>, D::Error> {
        Vec::<String>::deserialize(deserializer)?.iter().map(|s| from_hex(s).map_err(D::Error::custom)).collect()
    }
}
