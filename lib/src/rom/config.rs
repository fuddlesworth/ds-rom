use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Config file mainly consisting of paths to extracted files.
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfig {
    /// Path to header YAML, deserializes into [`Header`](crate::rom::Header).
    pub header: PathBuf,
    /// Path to header logo PNG, loaded by [`Logo::from_png`](crate::rom::Logo::from_png).
    pub header_logo: PathBuf,

    /// Path to ARM9 binary
    pub arm9_bin: PathBuf,
    /// Path to ARM9 YAML, deserializes into [`Arm9BuildConfig`](crate::rom::Arm9BuildConfig).
    pub arm9_config: PathBuf,

    /// Path to ARM7 binary
    pub arm7_bin: PathBuf,
    /// Path to ARM7 YAML, deserializes into [`Arm7Offsets`](crate::rom::Arm7Offsets).
    pub arm7_config: PathBuf,

    /// Path to ITCM files
    pub itcm: RomConfigAutoload,
    /// Path to DTCM files
    pub dtcm: RomConfigAutoload,
    /// Path to unknown autoloads
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub unknown_autoloads: Vec<RomConfigUnknownAutoload>,

    /// Path to ARM9 overlays YAML, deserializes into [`OverlayTableConfig`](crate::rom::OverlayTableConfig).
    pub arm9_overlays: Option<PathBuf>,
    /// Path to ARM7 overlays YAML, deserializes into [`OverlayTableConfig`](crate::rom::OverlayTableConfig).
    pub arm7_overlays: Option<PathBuf>,

    /// Path to banner YAML, deserializes into [`Banner`](crate::rom::Banner).
    pub banner: PathBuf,

    /// Path to asset files directory
    pub files_dir: PathBuf,
    /// Path to path order file
    pub path_order: PathBuf,

    /// Path to HMAC SHA1 key file for ARM9
    pub arm9_hmac_sha1_key: Option<PathBuf>,

    /// Whether the ARM9 program is followed by a footer. DSi-enhanced titles built with the TWL-SDK have no footer.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub arm9_footer: bool,

    /// DSi-specific parts of DSi-enhanced and DSi-exclusive ROMs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsi: Option<RomConfigDsi>,

    /// Path to multiboot signature YAML
    pub multiboot_signature: Option<PathBuf>,

    /// Alignment of ROM sections
    pub alignment: RomConfigAlignment,

    /// Padding values for aligning ROM sections
    pub padding: RomConfigPaddingValues,
}

/// Path to autoload files
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigAutoload {
    /// Path to binary
    pub bin: PathBuf,
    /// Path to YAML, deserializes into [`AutoloadInfo`](crate::rom::raw::AutoloadInfo).
    pub config: PathBuf,
}

/// Path to unknown autoload files
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigUnknownAutoload {
    /// Index of the autoload in the autoload table
    pub index: u32,
    /// Path to extracted files
    #[serde(flatten)]
    pub files: RomConfigAutoload,
}

/// Alignment of ROM sections.
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigAlignment {
    /// Alignment of the ARM9 program.
    pub arm9: u32,
    /// Alignment of the ARM9 overlay table.
    pub arm9_overlay_table: u32,
    /// Alignment of each ARM9 overlay file.
    pub arm9_overlay: u32,
    /// Alignment of the ARM7 program.
    pub arm7: u32,
    /// Alignment of the ARM7 overlay table.
    pub arm7_overlay_table: u32,
    /// Alignment of each ARM7 overlay file.
    pub arm7_overlay: u32,
    /// Alignment of the file name table.
    pub file_name_table: u32,
    /// Alignment of the file allocation table.
    pub file_allocation_table: u32,
    /// Alignment of the banner.
    pub banner: u32,
    /// Alignment of the file image block.
    pub file_image_block: u32,
    /// Alignment of each file.
    pub file: u32,
}

/// Byte values to append when aligning ROM sections.
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigPaddingValues {
    /// Before the ARM9 program.
    pub arm9: u8,
    /// Before the ARM9 overlay table.
    pub arm9_overlay_table: u8,
    /// Before ARM9 overlays.
    pub arm9_overlays: u8,
    /// Before ARM7 program.
    pub arm7: u8,
    /// Before the ARM7 overlay table.
    pub arm7_overlay_table: u8,
    /// Before ARM7 overlays.
    pub arm7_overlays: u8,
    /// Before the file name table.
    pub fnt: u8,
    /// Before the file allocation table.
    pub fat: u8,
    /// Before the banner section.
    pub banner: u8,
    /// Before files in the file image block.
    pub file_image: u8,
    /// Aligning the ROM size to a power of two.
    pub rom: u8,
}

/// Paths to the DSi-specific parts of a ROM, see [`crate::rom::Dsi`].
#[derive(Serialize, Deserialize, Clone)]
pub struct RomConfigDsi {
    /// Path to the DSi config, see [`crate::rom::DsiConfig`].
    pub config: PathBuf,
    /// Path to the decrypted ARM9i program.
    pub arm9i: PathBuf,
    /// Path to the decrypted ARM7i program.
    pub arm7i: PathBuf,
    /// Path to the data between the start of the DSi region and the ARM9i program.
    pub region_prefix: PathBuf,
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}
