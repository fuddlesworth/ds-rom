use std::{
    mem::{offset_of, size_of},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use super::{
    BuildContext, Rom,
    raw::{
        self, AccessControl, Capacity, Delay, DsFlags, DsiFlags, DsiFlags2, HeaderVersion, ProgramOffset, RegionFlags,
        TableOffset,
    },
};
use crate::{
    crc::CRC_16_MODBUS,
    str::{AsciiArray, AsciiArrayError},
};
/// ROM header.
#[derive(Serialize, Deserialize, Default)]
pub struct Header {
    /// Values for the original header version, [`HeaderVersion::Original`].
    #[serde(flatten)]
    pub original: HeaderOriginal,
    /// Values for DS games after DSi release, [`HeaderVersion::DsPostDsi`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_post_dsi: Option<HeaderDsPostDsi>,
    /// Values for DSi-enhanced and DSi-exclusive games.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsi: Option<HeaderDsi>,
}

/// Values for the original header version, [`HeaderVersion::Original`].
#[derive(Serialize, Deserialize, Default)]
pub struct HeaderOriginal {
    /// Short game title, normally in uppercase letters.
    pub title: String,
    /// 4-character game code in uppercase letters.
    pub gamecode: AsciiArray<4>,
    /// 2-character maker code, normally "01".
    pub makercode: AsciiArray<2>,
    /// Unit code, depends on which platform (DS, DSi) this game is for.
    pub unitcode: u8,
    /// Encryption seed select.
    pub seed_select: u8,
    /// Flags for both DS and DSi.
    pub ds_flags: DsFlags,
    /// ROM version, usually zero.
    pub rom_version: u8,
    /// Autostart, can skip "Health and Safety" screen.
    pub autostart: u8,
    /// Port 0x40001a4 setting for normal commands.
    pub normal_cmd_setting: u32,
    /// Port 0x40001a4 setting for KEY1 commands.
    pub key1_cmd_setting: u32,
    /// Delay to wait for secure area.
    pub secure_area_delay: Delay,
    /// NAND end of ROM area in multiples of 0x20000 (0x80000 on DSi).
    pub rom_nand_end: u16,
    /// NAND end of RW area in multiples of 0x20000 (0x80000 on DSi).
    pub rw_nand_end: u16,
    /// Whether the header has the ARM9 build info offset.
    pub has_arm9_build_info_offset: bool,
}

/// Values for DS games after DSi release, [`HeaderVersion::DsPostDsi`].
#[derive(Serialize, Deserialize)]
pub struct HeaderDsPostDsi {
    /// DSi-exclusive flags.
    pub dsi_flags_2: DsiFlags2,
    /// SHA1-HMAC of banner.
    pub sha1_hmac_banner: [u8; 0x14],
    /// Unknown SHA1-HMAC, defined by some games.
    pub sha1_hmac_unk1: [u8; 0x14],
    /// Unknown SHA1-HMAC, defined by some games.
    pub sha1_hmac_unk2: [u8; 0x14],
    /// RSA-SHA1 signature up to [`raw::Header::debug_args`].
    pub rsa_sha1: Box<[u8]>,
}

/// Values for DSi-enhanced and DSi-exclusive games. Values which depend on the ROM layout are computed when building.
#[derive(Serialize, Deserialize)]
pub struct HeaderDsi {
    /// DSi-specific flags, see [`DsiFlags`].
    pub dsi_flags: u8,
    /// MBK1 to MBK5
    pub memory_banks_wram: [u32; 5],
    /// MBK6 to MBK8
    pub memory_banks_arm9: [u32; 3],
    /// MBK6 to MBK8
    pub memory_banks_arm7: [u32; 3],
    /// MBK9
    pub memory_bank_9: u32,
    /// Region flags, see [`RegionFlags`].
    pub region_flags: u32,
    /// Access control, see [`AccessControl`].
    pub access_control: u32,
    /// ARM7 SCFG_EXT7 setting.
    pub arm7_scfg_ext7_setting: u32,
    /// SD/MMC size of shared2/0000 file
    pub sd_shared2_0000_size: u8,
    /// SD/MMC size of shared2/0001 file
    pub sd_shared2_0001_size: u8,
    /// EULA version.
    pub eula_version: u8,
    /// Use age ratings.
    pub use_ratings: bool,
    /// SD/MMC size of shared/0002 file
    pub sd_shared2_0002_size: u8,
    /// SD/MMC size of shared/0003 file
    pub sd_shared2_0003_size: u8,
    /// SD/MMC size of shared/0004 file
    pub sd_shared2_0004_size: u8,
    /// SD/MMC size of shared/0005 file
    pub sd_shared2_0005_size: u8,
    /// File type.
    pub file_type: u32,
    /// SD/MMC public.sav file size.
    pub sd_public_sav_size: u32,
    /// SD/MMC private.sav file size.
    pub sd_private_sav_size: u32,
    /// Age ratings.
    pub age_ratings: [u8; 0x10],
}

/// Errors related to [`Header::build`].
#[derive(Snafu, Debug)]
pub enum HeaderBuildError {
    /// See [`AsciiArrayError`].
    #[snafu(transparent)]
    AsciiArray {
        /// Source error.
        source: AsciiArrayError,
    },
}

impl Header {
    /// Loads from a raw header.
    pub fn load_raw(header: &raw::Header) -> Self {
        let version = header.version();
        Self {
            original: HeaderOriginal {
                title: header.title.to_string(),
                gamecode: header.gamecode,
                makercode: header.makercode,
                unitcode: header.unitcode,
                seed_select: header.seed_select,
                ds_flags: header.ds_flags,
                rom_version: header.rom_version,
                autostart: header.autostart,
                normal_cmd_setting: header.normal_cmd_setting,
                key1_cmd_setting: header.key1_cmd_setting,
                secure_area_delay: header.secure_area_delay,
                rom_nand_end: header.rom_nand_end,
                rw_nand_end: header.rw_nand_end,
                has_arm9_build_info_offset: header.arm9_build_info_offset != 0,
            },
            ds_post_dsi: (version >= HeaderVersion::DsPostDsi).then_some(HeaderDsPostDsi {
                dsi_flags_2: header.dsi_flags_2,
                sha1_hmac_banner: header.sha1_hmac_banner,
                sha1_hmac_unk1: header.sha1_hmac_unk1,
                sha1_hmac_unk2: header.sha1_hmac_unk2,
                rsa_sha1: Box::new(header.rsa_sha1),
            }),
            dsi: header.is_dsi().then(|| HeaderDsi {
                dsi_flags: header.dsi_flags.into_bits(),
                memory_banks_wram: header.memory_banks_wram,
                memory_banks_arm9: header.memory_banks_arm9,
                memory_banks_arm7: header.memory_banks_arm7,
                memory_bank_9: header.memory_bank_9,
                region_flags: header.region_flags.into_bits(),
                access_control: header.access_control.into_bits(),
                arm7_scfg_ext7_setting: header.arm7_scfg_ext7_setting,
                sd_shared2_0000_size: header.sd_shared2_0000_size,
                sd_shared2_0001_size: header.sd_shared2_0001_size,
                eula_version: header.eula_version,
                use_ratings: header.use_ratings,
                sd_shared2_0002_size: header.sd_shared2_0002_size,
                sd_shared2_0003_size: header.sd_shared2_0003_size,
                sd_shared2_0004_size: header.sd_shared2_0004_size,
                sd_shared2_0005_size: header.sd_shared2_0005_size,
                file_type: header.file_type,
                sd_public_sav_size: header.sd_public_sav_size,
                sd_private_sav_size: header.sd_private_sav_size,
                age_ratings: header.age_ratings,
            }),
        }
    }

    /// Builds a raw header.
    ///
    /// # Panics
    ///
    /// Panics if a value is missing in the `context`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the title contains a non-ASCII character.
    pub fn build(&self, context: &BuildContext, rom: &Rom) -> Result<raw::Header, HeaderBuildError> {
        let logo = rom.header_logo().compress();
        let arm9 = rom.arm9();
        let arm7 = rom.arm7();
        let arm9_offset = context.arm9_offset.expect("ARM9 offset must be known");
        let arm7_offset = context.arm7_offset.expect("ARM7 offset must be known");
        let mut header = raw::Header {
            title: AsciiArray::from_str(&self.original.title)?,
            gamecode: self.original.gamecode,
            makercode: self.original.makercode,
            unitcode: self.original.unitcode,
            seed_select: self.original.seed_select,
            capacity: Capacity::from_size(context.rom_size.expect("ROM size must be known")),
            reserved0: [0; 7],
            dsi_flags: DsiFlags::new(),
            ds_flags: self.original.ds_flags,
            rom_version: self.original.rom_version,
            autostart: self.original.autostart,
            arm9: ProgramOffset {
                offset: arm9_offset,
                entry: arm9.entry_function(),
                base_addr: arm9.base_address(),
                size: arm9.full_data().len() as u32,
            },
            arm7: ProgramOffset {
                offset: arm7_offset,
                entry: arm7.entry_function(),
                base_addr: arm7.base_address(),
                size: arm7.full_data().len() as u32,
            },
            file_names: context.fnt_offset.expect("FNT offset must be known"),
            file_allocs: context.fat_offset.expect("FAT offset must be known"),
            arm9_overlays: context.arm9_ovt_offset.unwrap_or_default(),
            arm7_overlays: context.arm7_ovt_offset.unwrap_or_default(),
            normal_cmd_setting: self.original.normal_cmd_setting,
            key1_cmd_setting: self.original.key1_cmd_setting,
            banner_offset: context.banner_offset.map(|b| b.offset).expect("Banner offset must be known"),
            secure_area_crc: if let Some(key) = context.blowfish_key {
                arm9.secure_area_crc(key, self.original.gamecode.to_le_u32())
            } else {
                0
            },
            secure_area_delay: self.original.secure_area_delay,
            arm9_autoload_callback: context.arm9_autoload_callback.expect("ARM9 autoload callback must be known"),
            arm7_autoload_callback: context.arm7_autoload_callback.expect("ARM7 autoload callback must be known"),
            secure_area_disable: 0,
            rom_size_ds: context.rom_size.expect("ROM size must be known"),
            header_size: size_of::<raw::Header>() as u32,
            // Build info offsets are relative to their program in DSi titles
            arm9_build_info_offset: match (self.original.has_arm9_build_info_offset, context.arm9_build_info_offset) {
                (false, _) | (true, None) => 0,
                (true, Some(offset)) if self.dsi.is_some() => offset,
                (true, Some(offset)) => offset + arm9_offset,
            },
            arm7_build_info_offset: match context.arm7_build_info_offset {
                None => 0,
                Some(offset) if self.dsi.is_some() => offset,
                Some(offset) => offset + arm7_offset,
            },
            ds_rom_region_end: 0,
            dsi_rom_region_end: 0,
            rom_nand_end: self.original.rom_nand_end,
            rw_nand_end: self.original.rw_nand_end,
            reserved1: [0; 0x18],
            reserved2: [0; 0x10],
            logo,
            logo_crc: CRC_16_MODBUS.checksum(&logo),
            header_crc: 0, // gets updated below
            debug_rom_offset: 0,
            debug_size: 0,
            debug_ram_addr: 0,
            reserved3: [0; 0x4],
            reserved4: [0; 0x10],
            // The below fields are for DSi only and are not supported yet
            memory_banks_wram: [0; 5],
            memory_banks_arm9: [0; 3],
            memory_banks_arm7: [0; 3],
            memory_bank_9: 0,
            region_flags: RegionFlags::new(),
            access_control: AccessControl::new(),
            arm7_scfg_ext7_setting: 0,
            dsi_flags_2: DsiFlags2::new(),
            arm9i: ProgramOffset::default(),
            arm7i: ProgramOffset::default(),
            digest_ds_area: TableOffset::default(),
            digest_dsi_area: TableOffset::default(),
            digest_sector_hashtable: TableOffset::default(),
            digest_block_hashtable: TableOffset::default(),
            digest_sector_size: 0,
            digest_sector_count: 0,
            banner_size: 0,
            sd_shared2_0000_size: 0,
            sd_shared2_0001_size: 0,
            eula_version: 0,
            use_ratings: false,
            rom_size_dsi: 0,
            sd_shared2_0002_size: 0,
            sd_shared2_0003_size: 0,
            sd_shared2_0004_size: 0,
            sd_shared2_0005_size: 0,
            arm9i_build_info_offset: 0,
            arm7i_build_info_offset: 0,
            modcrypt_area_1: TableOffset::default(),
            modcrypt_area_2: TableOffset::default(),
            gamecode_rev: AsciiArray([0; 4]),
            file_type: 0,
            sd_public_sav_size: 0,
            sd_private_sav_size: 0,
            reserved5: [0; 0xb0],
            age_ratings: [0; 0x10],
            sha1_hmac_arm9_with_secure_area: [0; 0x14],
            sha1_hmac_arm7: [0; 0x14],
            sha1_hmac_digest: [0; 0x14],
            sha1_hmac_banner: [0; 0x14],
            sha1_hmac_arm9i: [0; 0x14],
            sha1_hmac_arm7i: [0; 0x14],
            sha1_hmac_unk1: [0; 0x14],
            sha1_hmac_unk2: [0; 0x14],
            sha1_hmac_arm9: [0; 0x14],
            reserved6: [0; 0xa4c],
            debug_args: [0; 0x180],
            rsa_sha1: [0; 0x80],
            reserved7: [0; 0x3000],
        };

        if let Some(ds_post_dsi) = &self.ds_post_dsi {
            header.dsi_flags_2 = ds_post_dsi.dsi_flags_2;
            header.sha1_hmac_banner = ds_post_dsi.sha1_hmac_banner;
            header.sha1_hmac_unk1 = ds_post_dsi.sha1_hmac_unk1;
            header.sha1_hmac_unk2 = ds_post_dsi.sha1_hmac_unk2;
            header.rsa_sha1.copy_from_slice(&ds_post_dsi.rsa_sha1);
        }

        if let (Some(dsi), Some(values)) = (&self.dsi, &context.dsi) {
            let layout = &values.layout;
            header.capacity = Capacity::from_size(layout.rom_size_dsi);
            header.dsi_flags = DsiFlags::from_bits(dsi.dsi_flags);
            if header.secure_area_crc == 0 {
                header.secure_area_crc = values.secure_area_crc.unwrap_or(0);
            }
            header.rom_size_ds = layout.rom_size_ds;
            header.ds_rom_region_end = (layout.dsi_region_start / DSI_REGION_UNIT) as u16;
            header.dsi_rom_region_end = (layout.dsi_region_start / DSI_REGION_UNIT) as u16;
            header.memory_banks_wram = dsi.memory_banks_wram;
            header.memory_banks_arm9 = dsi.memory_banks_arm9;
            header.memory_banks_arm7 = dsi.memory_banks_arm7;
            header.memory_bank_9 = dsi.memory_bank_9;
            header.region_flags = RegionFlags::from_bits(dsi.region_flags);
            header.access_control = AccessControl::from_bits(dsi.access_control);
            header.arm7_scfg_ext7_setting = dsi.arm7_scfg_ext7_setting;
            header.arm9i = layout.arm9i;
            header.arm7i = layout.arm7i;
            header.digest_ds_area = layout.digest_ds_area;
            header.digest_dsi_area = layout.digest_dsi_area;
            header.digest_sector_hashtable = layout.digest_sector_hashtable;
            header.digest_block_hashtable = layout.digest_block_hashtable;
            if let Some(dsi_rom) = rom.dsi() {
                header.digest_sector_size = dsi_rom.config().digest_sector_size;
                header.digest_sector_count = dsi_rom.config().digest_sector_count;
                header.arm9i_build_info_offset = dsi_rom.config().arm9i.build_info;
                header.arm7i_build_info_offset = dsi_rom.config().arm7i.build_info;
            }
            header.banner_size = context.banner_offset.map(|b| b.size).unwrap_or(0);
            header.sd_shared2_0000_size = dsi.sd_shared2_0000_size;
            header.sd_shared2_0001_size = dsi.sd_shared2_0001_size;
            header.eula_version = dsi.eula_version;
            header.use_ratings = dsi.use_ratings;
            header.rom_size_dsi = layout.rom_size_dsi;
            header.sd_shared2_0002_size = dsi.sd_shared2_0002_size;
            header.sd_shared2_0003_size = dsi.sd_shared2_0003_size;
            header.sd_shared2_0004_size = dsi.sd_shared2_0004_size;
            header.sd_shared2_0005_size = dsi.sd_shared2_0005_size;
            header.modcrypt_area_1 = values.modcrypt_area_1;
            header.modcrypt_area_2 = values.modcrypt_area_2;
            let mut gamecode_rev = self.original.gamecode;
            gamecode_rev.0.reverse();
            header.gamecode_rev = gamecode_rev;
            header.file_type = dsi.file_type;
            header.sd_public_sav_size = dsi.sd_public_sav_size;
            header.sd_private_sav_size = dsi.sd_private_sav_size;
            header.age_ratings = dsi.age_ratings;
            header.sha1_hmac_arm9_with_secure_area = values.sha1_hmac_arm9_with_secure_area;
            header.sha1_hmac_arm7 = values.sha1_hmac_arm7;
            header.sha1_hmac_digest = values.sha1_hmac_digest;
            header.sha1_hmac_banner = values.sha1_hmac_banner;
            header.sha1_hmac_arm9i = values.sha1_hmac_arm9i;
            header.sha1_hmac_arm7i = values.sha1_hmac_arm7i;
            header.sha1_hmac_arm9 = values.sha1_hmac_arm9;
        }

        header.header_crc = CRC_16_MODBUS.checksum(&bytemuck::bytes_of(&header)[0..offset_of!(raw::Header, header_crc)]);
        Ok(header)
    }

    /// Returns the version of this [`Header`].
    pub fn version(&self) -> HeaderVersion {
        if self.ds_post_dsi.is_some() {
            HeaderVersion::DsPostDsi
        } else {
            HeaderVersion::Original
        }
    }
}

/// The DS and DSi region boundaries in the header are in units of this size.
const DSI_REGION_UNIT: u32 = 0x80000;
