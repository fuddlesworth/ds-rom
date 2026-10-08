use std::{
    backtrace::Backtrace,
    io::{self, Cursor, Write},
    mem::size_of,
    path::Path,
};

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use super::{
    Arm7, Arm9, Arm9AutoloadError, Arm9Error, Arm9HmacSha1KeyError, Arm9Offsets, Arm9OverlaySignaturesError, Autoload, Banner,
    BannerError, BannerImageError, BuildInfo, Dsi, DsiConfig, DsiError, DsiHeaderValues, FileBuildError, FileParseError,
    FileSystem, Header, HeaderBuildError, Logo, LogoError, LogoLoadError, LogoSaveError, Ltd, Overlay, OverlayError,
    OverlayInfo, OverlayOptions, OverlayTable, RomConfigAutoload, RomConfigUnknownAutoload,
    raw::{
        self, Arm9Footer, HmacSha1Signature, RawArm9Error, RawBannerError, RawBuildInfoError, RawFatError, RawFntError,
        RawHeaderError, RawOverlayError, RomAlignmentsError, TableOffset,
    },
};
use crate::{
    compress::lz77::Lz77DecompressError,
    crypto::{
        blowfish::BlowfishKey,
        dsprot::{DsProtDecryptOptions, DsProtEncryptOptions, DsProtState},
        hmac_sha1::{HmacSha1, HmacSha1FromBytesError},
    },
    io::{FileError, create_dir_all, create_file, create_file_and_dirs, open_file, read_file, read_to_string},
    rom::{
        Arm9DsProtInfoError, Arm9WithTcmsOptions, OverlayDsProtError, RomConfig, RomConfigDsi,
        raw::{FileAlloc, MultibootSignature, RawMultibootSignatureError},
    },
};

/// A plain ROM.
pub struct Rom<'a> {
    header: Header,
    header_logo: Logo,
    arm9: Arm9<'a>,
    arm9_overlay_table: OverlayTable<'a>,
    arm7: Arm7<'a>,
    arm7_overlay_table: OverlayTable<'a>,
    banner: Banner,
    files: FileSystem<'a>,
    multiboot_signature: Option<MultibootSignature>,
    dsi: Option<Dsi<'a>>,
    hmac_sha1: Option<HmacSha1>,

    path_order: Vec<String>,
    config: RomConfig,
}

/// Errors related to [`Rom::extract`].
#[derive(Debug, Snafu)]
pub enum RomExtractError {
    /// See [`DsiError`].
    #[snafu(transparent)]
    Dsi {
        /// Source error.
        source: DsiError,
    },
    /// Occurs when a DSi ROM has no ARM9 HMAC-SHA1 key, which is needed to build its digests and SHA1-HMACs.
    #[snafu(display("the DSi ROM has no ARM9 HMAC-SHA1 key, which is needed to rebuild its digests:\n{backtrace}"))]
    NoDsiHmacSha1Key {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`RawHeaderError`].
    #[snafu(transparent)]
    RawHeader {
        /// Source error.
        source: RawHeaderError,
    },
    /// See [`LogoError`].
    #[snafu(transparent)]
    Logo {
        /// Source error.
        source: LogoError,
    },
    /// See [`RawOverlayError`].
    #[snafu(transparent)]
    RawOverlay {
        /// Source error.
        source: RawOverlayError,
    },
    /// See [`RawFntError`].
    #[snafu(transparent)]
    RawFnt {
        /// Source error.
        source: RawFntError,
    },
    /// See [`RawFatError`].
    #[snafu(transparent)]
    RawFat {
        /// Source error.
        source: RawFatError,
    },
    /// See [`RawBannerError`].
    #[snafu(transparent)]
    RawBanner {
        /// Source error.
        source: RawBannerError,
    },
    /// See [`FileParseError`].
    #[snafu(transparent)]
    FileParse {
        /// Source error.
        source: FileParseError,
    },
    /// See [`RawArm9Error`].
    #[snafu(transparent)]
    RawArm9 {
        /// Source error.
        source: RawArm9Error,
    },
    /// See [`Arm9AutoloadError`]
    #[snafu(transparent)]
    Arm9Autoload {
        /// Source error.
        source: Arm9AutoloadError,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// See [`RomAlignmentsError`].
    #[snafu(transparent)]
    RomAlignments {
        /// Source error.
        source: RomAlignmentsError,
    },
    /// See [`OverlayError`].
    #[snafu(transparent)]
    Overlay {
        /// Source error.
        source: OverlayError,
    },
    /// See [`Arm9HmacSha1KeyError`].
    #[snafu(transparent)]
    Arm9HmacSha1Key {
        /// Source error.
        source: Arm9HmacSha1KeyError,
    },
    /// See [`RawMultibootSignatureError`].
    #[snafu(transparent)]
    RawMultibootSignature {
        /// Source error.
        source: RawMultibootSignatureError,
    },
    /// See [`Arm9DsProtInfoError`].
    #[snafu(transparent)]
    Arm9DsProtInfo {
        /// Source error.
        source: Arm9DsProtInfoError,
    },
    /// See [`OverlayDsProtError`].
    #[snafu(transparent)]
    OverlayDsProt {
        /// Source error.
        source: OverlayDsProtError,
    },
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
    },
}

/// Errors related to [`Rom::build`].
#[derive(Snafu, Debug)]
pub enum RomBuildError {
    /// See [`DsiError`].
    #[snafu(transparent)]
    Dsi {
        /// Source error.
        source: DsiError,
    },
    /// Occurs when only one of the header's DSi section and the ROM's DSi area is present.
    #[snafu(display(
        "a DSi ROM needs both a DSi header section and a DSi area, but only the {present} is present:\n{backtrace}"
    ))]
    DsiIncomplete {
        /// The part which is present.
        present: &'static str,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when building a DSi ROM without the ARM9 HMAC-SHA1 key, which is needed for its digests and SHA1-HMACs.
    #[snafu(display("the ARM9 HMAC-SHA1 key is needed to build DSi ROMs:\n{backtrace}"))]
    DsiHmacSha1KeyNeeded {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// See [`FileBuildError`].
    #[snafu(transparent)]
    FileBuild {
        /// Source error.
        source: FileBuildError,
    },
    /// See [`BannerError`].
    #[snafu(transparent)]
    Banner {
        /// Source error.
        source: BannerError,
    },
    /// See [`HeaderBuildError`].
    #[snafu(transparent)]
    HeaderBuild {
        /// Source error.
        source: HeaderBuildError,
    },
}

/// Errors related to [`Rom::save`] and [`Rom::load`].
#[derive(Snafu, Debug)]
pub enum RomSaveError {
    /// See [`DsiError`].
    #[snafu(transparent)]
    Dsi {
        /// Source error.
        source: DsiError,
    },
    /// Occurs when the ROM is encrypted but no Blowfish key was provided.
    #[snafu(display("blowfish key is required because ARM9 program is encrypted"))]
    BlowfishKeyNeeded,
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Source error.
        source: io::Error,
    },
    /// See [`FileError`].
    #[snafu(transparent)]
    File {
        /// Source error.
        source: FileError,
    },
    /// See [`serde_saphyr::Error`].
    #[snafu(transparent)]
    SerdeSaphyrDeserialize {
        /// Source error.
        source: serde_saphyr::Error,
    },
    /// See [`serde_saphyr::ser_error::Error`].
    #[snafu(transparent)]
    SerdeSaphyrSerialize {
        /// Source error.
        source: serde_saphyr::ser_error::Error,
    },
    /// See [`LogoSaveError`].
    #[snafu(transparent)]
    LogoSave {
        /// Source error.
        source: LogoSaveError,
    },
    /// See [`LogoLoadError`].
    #[snafu(transparent)]
    LogoLoad {
        /// Source error.
        source: LogoLoadError,
    },
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// See [`Arm9Error`].
    #[snafu(transparent)]
    Arm9 {
        /// Source error.
        source: Arm9Error,
    },
    /// See [`Arm9AutoloadError`].
    #[snafu(transparent)]
    Arm9Autoload {
        /// Source error.
        source: Arm9AutoloadError,
    },
    /// See [`BannerImageError`].
    #[snafu(transparent)]
    BannerImage {
        /// Source error.
        source: BannerImageError,
    },
    /// See [`Lz77DecompressError`].
    #[snafu(transparent)]
    Lz77Decompress {
        /// Source error.
        source: Lz77DecompressError,
    },
    /// See [`OverlayError`].
    #[snafu(transparent)]
    Overlay {
        /// Source error.
        source: OverlayError,
    },
    /// See [`Arm9OverlaySignaturesError`].
    #[snafu(transparent)]
    HmacSha1FromBytes {
        /// Source error.
        source: HmacSha1FromBytesError,
    },
    /// See [`Arm9HmacSha1KeyError`].
    #[snafu(transparent)]
    Arm9HmacSha1Key {
        /// Source error.
        source: Arm9HmacSha1KeyError,
    },
    /// See [`Arm9OverlaySignaturesError`].
    #[snafu(transparent)]
    Arm9OverlaySignatures {
        /// Source error.
        source: Arm9OverlaySignaturesError,
    },
    /// Occurs when the HMAC-SHA1 key was not provided for a signed overlay.
    #[snafu(display("HMAC-SHA1 key was not provided for a signed overlay:\n{backtrace}"))]
    NoHmacSha1Key {
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when an autoload was not found in the config.
    #[snafu(display("autoload index {index} not found in config:\n{backtrace}"))]
    AutoloadNotFound {
        /// The index of the autoload that was missing.
        index: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// See [`Arm9DsProtInfoError`].
    #[snafu(transparent)]
    Arm9DsProtInfo {
        /// Source error.
        source: Arm9DsProtInfoError,
    },
    /// See [`OverlayDsProtError`].
    #[snafu(transparent)]
    OverlayDsProt {
        /// Source error.
        source: OverlayDsProtError,
    },
}

/// Config file for the ARM9 main module.
#[derive(Serialize, Deserialize)]
pub struct Arm9BuildConfig {
    /// Various offsets within the ARM9 module.
    #[serde(flatten)]
    pub offsets: Arm9Offsets,
    /// Whether this module is encrypted in the ROM.
    pub encrypted: bool,
    /// Whether this module is compressed in the ROM.
    pub compressed: bool,
    /// Build info for this module.
    #[serde(flatten)]
    pub build_info: BuildInfo,
    /// Information about DS Protect.
    #[serde(default, skip_serializing_if = "DsProtState::is_none")]
    pub dsprot_state: DsProtState,
}

/// Overlay configuration, extending [`OverlayInfo`] with more fields.
#[derive(Serialize, Deserialize)]
pub struct OverlayConfig {
    /// See [`OverlayInfo`].
    #[serde(flatten)]
    pub info: OverlayInfo,
    /// Whether this overlay is signed.
    pub signed: bool,
    /// Name of binary file.
    pub file_name: String,
    /// Stores information about DS Protect functions that were decrypted in this overlay.
    #[serde(default, skip_serializing_if = "DsProtState::is_none")]
    pub dsprot: DsProtState,
}

/// Configuration for the overlay table, used for both ARM9 and ARM7 overlays.
#[derive(Serialize, Deserialize)]
pub struct OverlayTableConfig {
    /// Whether the overlay table has an HMAC-SHA1 signature.
    pub table_signed: bool,
    /// Overlay table HMAC-SHA1 signature. NOTE: This field is temporary! A bug in the DS standard library causes this
    /// signature to be computed incorrectly, and we haven't replicated this bug in our code yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_signature: Option<HmacSha1Signature>,
    /// List of overlays.
    pub overlays: Vec<OverlayConfig>,
}

impl<'a> Rom<'a> {
    /// Loads a ROM from a path generated by [`Self::save`].
    ///
    /// # Errors
    ///
    /// This function will return an error if there's a file missing or the file has an invalid format.
    pub fn load<P: AsRef<Path>>(config_path: P, options: RomLoadOptions) -> Result<Self, RomSaveError> {
        let config_path = config_path.as_ref();
        log::info!("Loading ROM from {}", config_path.display());

        let config: RomConfig = serde_saphyr::from_reader(open_file(config_path)?)?;
        let path = config_path.parent().unwrap();

        // --------------------- Load header ---------------------
        let (header, header_logo) = if options.load_header {
            let header: Header = serde_saphyr::from_reader(open_file(path.join(&config.header))?)?;
            let header_logo = Logo::from_png(path.join(&config.header_logo))?;
            (header, header_logo)
        } else {
            Default::default()
        };

        // --------------------- Load ARM9 program ---------------------
        let arm9_build_config: Arm9BuildConfig = serde_saphyr::from_reader(open_file(path.join(&config.arm9_config))?)?;
        let arm9 = read_file(path.join(&config.arm9_bin))?;

        // --------------------- Load autoloads ---------------------
        let mut autoloads = vec![];

        let itcm = read_file(path.join(&config.itcm.bin))?;
        let itcm_info = serde_saphyr::from_reader(open_file(path.join(&config.itcm.config))?)?;
        let itcm = Autoload::new(itcm, itcm_info);
        autoloads.push(itcm);

        let dtcm = read_file(path.join(&config.dtcm.bin))?;
        let dtcm_info = serde_saphyr::from_reader(open_file(path.join(&config.dtcm.config))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info);
        autoloads.push(dtcm);

        for unknown_autoload in &config.unknown_autoloads {
            let autoload = read_file(path.join(&unknown_autoload.files.bin))?;
            let autoload_info = serde_saphyr::from_reader(open_file(path.join(&unknown_autoload.files.config))?)?;
            let autoload = Autoload::new(autoload, autoload_info);
            autoloads.push(autoload);
        }

        autoloads.sort_by_key(|autoload| autoload.kind());

        // --------------------- Load HMAC SHA1 key ---------------------
        let arm9_hmac_sha1 = if let Some(hmac_sha1_key_file) = &config.arm9_hmac_sha1_key {
            let hmac_sha1_key = read_file(path.join(hmac_sha1_key_file))?;
            Some(HmacSha1::try_from(hmac_sha1_key.as_ref())?)
        } else {
            None
        };

        // --------------------- Load ARM9 overlays ---------------------
        let arm9_overlays = if let Some(arm9_overlays_config) = &config.arm9_overlays {
            Self::load_overlays(&path.join(arm9_overlays_config), "arm9", arm9_hmac_sha1.clone(), &options)?
        } else {
            Default::default()
        };

        // --------------------- Load DSi-specific parts ---------------------
        // Loaded before the ARM9 program, which holds the parameters of the ARM9i program's LTD module
        let (dsi, ltd_params) = if let Some(dsi_config) = &config.dsi {
            let dsi_config_data: DsiConfig = serde_saphyr::from_reader(open_file(path.join(&dsi_config.config))?)?;
            let arm9i = read_file(path.join(&dsi_config.arm9i))?;
            let arm7i = read_file(path.join(&dsi_config.arm7i))?;
            let region_prefix = read_file(path.join(&dsi_config.region_prefix))?;
            if dsi_config_data.ltd.is_some() {
                let mut autoloads = vec![];
                for files in &dsi_config.ltd_autoloads {
                    let data = read_file(path.join(&files.files.bin))?;
                    let info = serde_saphyr::from_reader(open_file(path.join(&files.files.config))?)?;
                    autoloads.push(Autoload::new(data, info));
                }
                let (dsi, params) = Dsi::with_ltd(Ltd::new(arm9i, autoloads), arm7i, region_prefix, dsi_config_data)?;
                (Some(dsi), Some(params))
            } else {
                (Some(Dsi::new(arm9i, arm7i, region_prefix, dsi_config_data)), None)
            }
        } else {
            (None, None)
        };

        // --------------------- Build ARM9 program ---------------------
        let mut arm9 = Arm9::with_autoloads(arm9, &autoloads, arm9_build_config.offsets, Arm9WithTcmsOptions {
            originally_compressed: arm9_build_config.compressed,
            originally_encrypted: arm9_build_config.encrypted,
            dsprot_state: arm9_build_config.dsprot_state,
        })?;
        arm9_build_config.build_info.assign_to_raw(arm9.build_info_mut()?);
        if let (Some(dsi), Some(params)) = (&dsi, &ltd_params) {
            arm9.write_ltd_params(dsi.config().arm9i.build_info, params);
        }
        arm9.update_overlay_signatures(&arm9_overlays)?;
        if arm9.dsprot_state().is_unencrypted() && options.encrypt {
            log::info!("Encrypting DS Protect in ARM9 program");
            arm9.encrypt_dsprot(&DsProtEncryptOptions::default())?;
        }
        if arm9_build_config.compressed && options.compress {
            log::info!("Compressing ARM9 program");
            arm9.compress()?;
        }
        if arm9_build_config.encrypted && options.encrypt {
            let Some(key) = options.key else {
                return BlowfishKeyNeededSnafu {}.fail();
            };
            log::info!("Encrypting ARM9 program");
            arm9.encrypt(key, header.original.gamecode.to_le_u32())?;
        }

        // --------------------- Load ARM7 overlays ---------------------
        let arm7_overlays = if let Some(arm7_overlays_config) = &config.arm7_overlays {
            Self::load_overlays(&path.join(arm7_overlays_config), "arm7", None, &options)?
        } else {
            Default::default()
        };

        // --------------------- Load ARM7 program ---------------------
        let arm7 = read_file(path.join(&config.arm7_bin))?;
        let arm7_config = serde_saphyr::from_reader(open_file(path.join(&config.arm7_config))?)?;
        let arm7 = Arm7::new(arm7, arm7_config);

        // --------------------- Load banner ---------------------
        let banner = if options.load_banner {
            let banner_path = path.join(&config.banner);
            let banner_dir = banner_path.parent().unwrap();
            let mut banner: Banner = serde_saphyr::from_reader(open_file(&banner_path)?)?;
            banner.images.load(banner_dir)?;
            banner
        } else {
            Default::default()
        };

        // --------------------- Load files ---------------------
        let num_overlays = arm9_overlays.overlays().len() + arm7_overlays.overlays().len();
        let (files, path_order) = if options.load_files {
            log::info!("Loading ROM assets");
            let files = FileSystem::load(path.join(&config.files_dir), num_overlays)?;
            let path_order =
                read_to_string(path.join(&config.path_order))?.trim().lines().map(|l| l.to_string()).collect::<Vec<_>>();
            (files, path_order)
        } else {
            (FileSystem::new(num_overlays), vec![])
        };

        // --------------------- Load multiboot signature ---------------------
        let multiboot_signature = if let Some(multiboot_signature) = config.multiboot_signature.as_ref() {
            serde_saphyr::from_reader(open_file(path.join(multiboot_signature))?)?
        } else {
            None
        };

        Ok(Self {
            header,
            header_logo,
            arm9,
            arm9_overlay_table: arm9_overlays,
            arm7,
            arm7_overlay_table: arm7_overlays,
            banner,
            files,
            path_order,
            multiboot_signature,
            dsi,
            hmac_sha1: arm9_hmac_sha1,
            config,
        })
    }

    fn load_overlays(
        config_path: &Path,
        processor: &str,
        hmac_sha1: Option<HmacSha1>,
        options: &RomLoadOptions,
    ) -> Result<OverlayTable<'a>, RomSaveError> {
        let path = config_path.parent().unwrap();
        let mut overlays = vec![];
        let overlay_table_config: OverlayTableConfig = serde_saphyr::from_reader(open_file(config_path)?)?;
        let num_overlays = overlay_table_config.overlays.len();
        for mut config in overlay_table_config.overlays.into_iter() {
            let data = read_file(path.join(config.file_name))?;
            let compressed = config.info.compressed;
            config.info.compressed = false;
            let mut overlay = Overlay::new(data, OverlayOptions {
                info: config.info,
                originally_compressed: compressed,
                originally_signed: config.signed,
                dsprot_state: config.dsprot,
            })?;

            if overlay.dsprot_state().is_unencrypted() && options.encrypt {
                log::info!("Encrypting DS Protect in {processor} overlay {}", overlay.id());
                overlay.encrypt_dsprot(&DsProtEncryptOptions::default())?;
            }

            if options.compress {
                if compressed {
                    log::info!("Compressing {processor} overlay {}/{}", overlay.id(), num_overlays - 1);
                    overlay.compress()?;
                }

                if config.signed {
                    let Some(ref hmac_sha1) = hmac_sha1 else {
                        return NoHmacSha1KeySnafu {}.fail();
                    };
                    overlay.sign(hmac_sha1)?;
                }
            }

            overlays.push(overlay);
        }

        let mut overlay_table = OverlayTable::new(overlays);
        if overlay_table_config.table_signed {
            if let Some(signature) = overlay_table_config.table_signature {
                overlay_table.set_signature(signature);
            } else {
                let Some(ref hmac_sha1) = hmac_sha1 else {
                    return NoHmacSha1KeySnafu {}.fail();
                };
                overlay_table.sign(hmac_sha1);
            }
        }

        Ok(overlay_table)
    }

    /// Saves this ROM to a path as separate files.
    ///
    /// # Errors
    ///
    /// This function will return an error if a file could not be created or the a component of the ROM has an invalid format.
    pub fn save<P: AsRef<Path>>(&self, path: P, key: Option<&BlowfishKey>) -> Result<(), RomSaveError> {
        let path = path.as_ref();
        create_dir_all(path)?;

        log::info!("Saving ROM to directory {}", path.display());

        // --------------------- Save config ---------------------
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join("config.yaml"))?, &self.config)?;

        // --------------------- Save header ---------------------
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&self.config.header))?, &self.header)?;
        self.header_logo.save_png(path.join(&self.config.header_logo))?;

        // --------------------- Save ARM9 program ---------------------
        let mut plain_arm9 = self.arm9.clone();
        if plain_arm9.is_encrypted() {
            let Some(key) = key else {
                return BlowfishKeyNeededSnafu {}.fail();
            };
            log::info!("Decrypting ARM9 program");
            plain_arm9.decrypt(key, self.header.original.gamecode.to_le_u32())?;
        }
        if plain_arm9.is_compressed()? {
            log::info!("Decompressing ARM9 program");
            plain_arm9.decompress()?;
        }
        if plain_arm9.dsprot_state().is_encrypted() {
            log::info!("Decrypting DS Protect in ARM9 program");
            plain_arm9.decrypt_dsprot(&DsProtDecryptOptions::default())?;
        }
        create_file_and_dirs(path.join(&self.config.arm9_bin))?.write_all(plain_arm9.code()?)?;
        let arm9_build_config = Arm9BuildConfig {
            offsets: *self.arm9.offsets(),
            encrypted: self.arm9.is_encrypted(),
            compressed: self.arm9.is_compressed()?,
            build_info: (*self.arm9.build_info()?).into(),
            dsprot_state: plain_arm9.dsprot_state().clone(),
        };
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&self.config.arm9_config))?, &arm9_build_config)?;

        // --------------------- Save ARM9 HMAC-SHA1 key ---------------------
        if let Some(arm9_hmac_sha1_key) = plain_arm9.hmac_sha1_key()? {
            if let Some(key_file) = &self.config.arm9_hmac_sha1_key {
                create_file_and_dirs(path.join(key_file))?.write_all(arm9_hmac_sha1_key.as_ref())?;
            }
        } else if self.config.arm9_hmac_sha1_key.is_some() {
            log::warn!("ARM9 HMAC-SHA1 key not found, but config requested it to be saved");
        }

        // --------------------- Save autoloads ---------------------
        for autoload in plain_arm9.autoloads()?.iter() {
            let (bin_path, config_path) = match autoload.kind() {
                raw::AutoloadKind::Itcm => (path.join(&self.config.itcm.bin), path.join(&self.config.itcm.config)),
                raw::AutoloadKind::Dtcm => (path.join(&self.config.dtcm.bin), path.join(&self.config.dtcm.config)),
                // LTD autoloads belong to the ARM9i program, not the ARM9 program
                raw::AutoloadKind::Ltd(index) => return AutoloadNotFoundSnafu { index }.fail(),
                raw::AutoloadKind::Unknown(index) => {
                    let unknown_autoload = self
                        .config
                        .unknown_autoloads
                        .iter()
                        .find(|autoload| autoload.index == index)
                        .ok_or_else(|| AutoloadNotFoundSnafu { index }.build())?;
                    (path.join(&unknown_autoload.files.bin), path.join(&unknown_autoload.files.config))
                }
            };
            create_file_and_dirs(bin_path)?.write_all(autoload.code())?;
            serde_saphyr::to_io_writer(&mut create_file_and_dirs(config_path)?, autoload.info())?;
        }

        // --------------------- Save ARM9 overlays ---------------------
        if let Some(arm9_overlays_config) = &self.config.arm9_overlays {
            Self::save_overlays(&path.join(arm9_overlays_config), &self.arm9_overlay_table, "arm9")?;
        }

        // --------------------- Save ARM7 program ---------------------
        create_file_and_dirs(path.join(&self.config.arm7_bin))?.write_all(self.arm7.full_data())?;
        serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&self.config.arm7_config))?, self.arm7.offsets())?;

        // --------------------- Save ARM7 overlays ---------------------
        if let Some(arm7_overlays_config) = &self.config.arm7_overlays {
            Self::save_overlays(&path.join(arm7_overlays_config), &self.arm7_overlay_table, "arm7")?;
        }

        // --------------------- Save banner ---------------------
        {
            let banner_path = path.join(&self.config.banner);
            let banner_dir = banner_path.parent().unwrap();
            serde_saphyr::to_io_writer(&mut create_file_and_dirs(&banner_path)?, &self.banner)?;
            self.banner.images.save_bitmap_file(banner_dir)?;
        }

        // --------------------- Save files ---------------------
        {
            log::info!("Saving ROM assets");
            let files_path = path.join(&self.config.files_dir);
            self.files.traverse_files(["/"], |file, path| {
                let path = files_path.join(path);
                // TODO: Rewrite traverse_files as an iterator so these errors can be returned
                create_dir_all(&path).expect("failed to create file directory");
                create_file(path.join(file.name()))
                    .expect("failed to create file")
                    .write_all(file.contents())
                    .expect("failed to write file");
            });
        }
        let mut path_order_file = create_file_and_dirs(path.join(&self.config.path_order))?;
        for path in &self.path_order {
            path_order_file.write_all(path.as_bytes())?;
            path_order_file.write_all("\n".as_bytes())?;
        }

        // --------------------- Save multiboot signature ---------------------
        if let Some(multiboot_signature) = &self.multiboot_signature {
            if let Some(signature_file) = &self.config.multiboot_signature {
                let file_path = path.join(signature_file);
                serde_saphyr::to_io_writer(&mut create_file_and_dirs(&file_path)?, multiboot_signature)?;
            }
        } else if self.config.multiboot_signature.is_some() {
            log::warn!("Multiboot signature not found, but config requested it to be saved");
        }

        // --------------------- Save DSi-specific parts ---------------------
        if let (Some(dsi), Some(dsi_config)) = (&self.dsi, &self.config.dsi) {
            serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&dsi_config.config))?, dsi.config())?;
            if let Some(ltd) = dsi.ltd() {
                create_file_and_dirs(path.join(&dsi_config.arm9i))?.write_all(ltd.static_data())?;
                for (autoload, files) in ltd.autoloads().iter().zip(&dsi_config.ltd_autoloads) {
                    create_file_and_dirs(path.join(&files.files.bin))?.write_all(autoload.full_data())?;
                    serde_saphyr::to_io_writer(&mut create_file_and_dirs(path.join(&files.files.config))?, autoload.info())?;
                }
            } else {
                create_file_and_dirs(path.join(&dsi_config.arm9i))?.write_all(dsi.arm9i())?;
            }
            create_file_and_dirs(path.join(&dsi_config.arm7i))?.write_all(dsi.arm7i())?;
            create_file_and_dirs(path.join(&dsi_config.region_prefix))?.write_all(dsi.region_prefix())?;
        }

        Ok(())
    }

    fn save_overlays(config_path: &Path, overlay_table: &OverlayTable, processor: &str) -> Result<(), RomSaveError> {
        let overlays = overlay_table.overlays();
        if !overlays.is_empty() {
            let overlays_path = config_path.parent().unwrap();
            create_dir_all(overlays_path)?;

            let mut configs = vec![];
            for overlay in overlays {
                let name = format!("ov{:03}", overlay.id());

                let mut plain_overlay = overlay.clone();
                if plain_overlay.is_compressed() {
                    log::info!("Decompressing {processor} overlay {}/{}", overlay.id(), overlays.len() - 1);
                    plain_overlay.decompress()?;
                }
                if plain_overlay.dsprot_state().is_encrypted() {
                    log::info!("Decrypting DS Protect in {processor} overlay {}", overlay.id());
                    plain_overlay.decrypt_dsprot(&DsProtDecryptOptions { decode_relocations: false })?;
                }

                configs.push(OverlayConfig {
                    info: overlay.info().clone(),
                    file_name: format!("{name}.bin"),
                    signed: plain_overlay.is_signed(),
                    dsprot: plain_overlay.dsprot_state().clone(),
                });

                create_file(overlays_path.join(format!("{name}.bin")))?.write_all(plain_overlay.code())?;
            }

            let overlay_table_config = OverlayTableConfig {
                table_signed: overlay_table.is_signed(),
                table_signature: overlay_table.signature(),
                overlays: configs,
            };
            serde_saphyr::to_io_writer(&mut create_file_and_dirs(config_path)?, &overlay_table_config)?;
        }
        Ok(())
    }

    /// Extracts from a raw ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if a component is missing from the raw ROM.
    pub fn extract(rom: &'a raw::Rom) -> Result<Self, RomExtractError> {
        let header = rom.header()?;
        log::info!("Extracting from {}", header.title);

        let fnt = rom.fnt()?;
        let fat = rom.fat()?;
        let banner = rom.banner()?;
        let file_root = FileSystem::parse(&fnt, fat, rom)?;
        let path_order = file_root.compute_path_order();

        let mut arm9 = rom.arm9()?;
        let mut decompressed_arm9 = arm9.clone();
        decompressed_arm9.decompress()?;
        // The layout of the autoload list can only be read from the decompressed program
        let autoload_layout = decompressed_arm9.detect_autoload_layout()?;
        arm9.set_twl_autoload_infos(autoload_layout == raw::AutoloadInfoLayout::Twl);

        let arm9_overlays = rom.arm9_overlay_table_with(&decompressed_arm9)?;
        let mut arm9_overlays = OverlayTable::parse_arm9(arm9_overlays, rom, &decompressed_arm9)?;
        let arm7_overlays = rom.arm7_overlay_table()?;
        let arm7_overlays = OverlayTable::parse_arm7(arm7_overlays, rom)?;

        let autoloads = decompressed_arm9.autoloads()?;
        let unknown_autoloads = autoloads
            .iter()
            .filter_map(|autoload| {
                let raw::AutoloadKind::Unknown(index) = autoload.kind() else {
                    return None;
                };
                Some(RomConfigUnknownAutoload {
                    index,
                    files: RomConfigAutoload {
                        bin: format!("arm9/unk_autoload_{index}.bin").into(),
                        config: format!("arm9/unk_autoload_{index}.yaml").into(),
                    },
                })
            })
            .collect();

        let arm9_hmac_sha1_key = decompressed_arm9.hmac_sha1_key()?;
        let has_arm9_hmac_sha1 = arm9_hmac_sha1_key.is_some();
        let arm9_footer = rom.arm9_footer_opt().map_err(RawArm9Error::from)?.is_some();
        let dsi = Dsi::extract(rom)?;
        if dsi.is_some() && !has_arm9_hmac_sha1 {
            return NoDsiHmacSha1KeySnafu {}.fail();
        }

        let multiboot_signature = rom.multiboot_signature()?;

        let alignment = rom.alignments()?;
        let padding = rom.padding_values()?;

        let dsprot_options = DsProtDecryptOptions::default();
        if let Some(result) = decompressed_arm9.decrypt_dsprot(&dsprot_options)? {
            arm9.set_dsprot_state(DsProtState::Encrypted(result.clone()));
        }
        for overlay in arm9_overlays.overlays_mut() {
            let mut decompressed_overlay = overlay.clone();
            decompressed_overlay.decompress()?;
            if let Some(result) = decompressed_overlay.decrypt_dsprot(&dsprot_options)? {
                overlay.set_dsprot_state(DsProtState::Encrypted(result.clone()));
            }
        }

        let config = RomConfig {
            header: "header.yaml".into(),
            header_logo: "header_logo.png".into(),
            arm9_bin: "arm9/arm9.bin".into(),
            arm9_config: "arm9/arm9.yaml".into(),
            arm7_bin: "arm7/arm7.bin".into(),
            arm7_config: "arm7/arm7.yaml".into(),
            itcm: RomConfigAutoload { bin: "arm9/itcm.bin".into(), config: "arm9/itcm.yaml".into() },
            unknown_autoloads,
            dtcm: RomConfigAutoload { bin: "arm9/dtcm.bin".into(), config: "arm9/dtcm.yaml".into() },
            arm9_overlays: if arm9_overlays.is_empty() {
                None
            } else {
                Some("arm9_overlays/overlays.yaml".into())
            },
            arm7_overlays: if arm7_overlays.is_empty() {
                None
            } else {
                Some("arm7_overlays/overlays.yaml".into())
            },
            banner: "banner/banner.yaml".into(),
            files_dir: "files/".into(),
            path_order: "path_order.txt".into(),
            multiboot_signature: if multiboot_signature.is_none() {
                None
            } else {
                Some("multiboot_signature.yaml".into())
            },
            arm9_hmac_sha1_key: has_arm9_hmac_sha1.then_some("arm9/hmac_sha1_key.bin".into()),
            arm9_footer,
            dsi: dsi.as_ref().map(|dsi| RomConfigDsi {
                config: "dsi/dsi.yaml".into(),
                arm9i: "dsi/arm9i.bin".into(),
                arm7i: "dsi/arm7i.bin".into(),
                region_prefix: "dsi/region_prefix.bin".into(),
                ltd_autoloads: dsi
                    .ltd()
                    .map(|ltd| {
                        (0..ltd.autoloads().len() as u32)
                            .map(|index| RomConfigUnknownAutoload {
                                index,
                                files: RomConfigAutoload {
                                    bin: format!("dsi/ltd_autoload_{index}.bin").into(),
                                    config: format!("dsi/ltd_autoload_{index}.yaml").into(),
                                },
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }),
            alignment,
            padding,
        };

        Ok(Self {
            header: Header::load_raw(header),
            header_logo: Logo::decompress(&header.logo)?,
            arm9,
            arm9_overlay_table: arm9_overlays,
            arm7: rom.arm7()?,
            arm7_overlay_table: arm7_overlays,
            banner: Banner::load_raw(&banner),
            files: file_root,
            multiboot_signature,
            dsi,
            hmac_sha1: arm9_hmac_sha1_key.map(HmacSha1::new),
            path_order,
            config,
        })
    }

    /// Builds a raw ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if an I/O operation fails or a component fails to build, or if a DSi ROM is
    /// incomplete or lacks its ARM9 HMAC-SHA1 key.
    pub fn build(mut self, key: Option<&BlowfishKey>) -> Result<raw::Rom<'a>, RomBuildError> {
        match (&self.header.dsi, &self.dsi) {
            (Some(_), None) => return DsiIncompleteSnafu { present: "header's DSi section" }.fail(),
            (None, Some(_)) => return DsiIncompleteSnafu { present: "DSi area" }.fail(),
            (Some(_), Some(_)) if self.hmac_sha1.is_none() => return DsiHmacSha1KeyNeededSnafu {}.fail(),
            _ => {}
        }

        let mut context = BuildContext { blowfish_key: key, ..Default::default() };

        let mut cursor = Cursor::new(Vec::with_capacity(128 * 1024)); // smallest possible ROM

        // --------------------- Write header placeholder ---------------------
        context.header_offset = Some(cursor.position() as u32);
        cursor.write_all(&[0u8; size_of::<raw::Header>()])?;

        // --------------------- Write ARM9 program ---------------------
        self.align(&mut cursor, self.config.alignment.arm9, self.config.padding.arm9)?;
        context.arm9_offset = Some(cursor.position() as u32);
        context.arm9_autoload_callback = Some(self.arm9.autoload_callback());
        context.arm9_build_info_offset = Some(self.arm9.build_info_offset());
        cursor.write_all(self.arm9.full_data())?;
        if self.config.arm9_footer {
            let footer = Arm9Footer::new(self.arm9.build_info_offset(), self.arm9.overlay_signatures_offset());
            cursor.write_all(bytemuck::bytes_of(&footer))?;
        }

        let max_file_id = self.files.max_file_id();
        let mut file_allocs = vec![FileAlloc::default(); max_file_id as usize + 1];

        if !self.arm9_overlay_table.is_empty() {
            // --------------------- Write ARM9 overlay table ---------------------
            self.align(&mut cursor, self.config.alignment.arm9_overlay_table, self.config.padding.arm9_overlay_table)?;
            context.arm9_ovt_offset = Some(TableOffset {
                offset: cursor.position() as u32,
                size: (self.arm9_overlay_table.len() * size_of::<raw::Overlay>()) as u32,
            });
            let raw_table = self.arm9_overlay_table.build();
            cursor.write_all(raw_table.as_bytes())?;

            // --------------------- Write ARM9 overlays ---------------------
            for overlay in self.arm9_overlay_table.overlays() {
                self.align(&mut cursor, self.config.alignment.arm9_overlay, self.config.padding.arm9_overlays)?;
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write_all(overlay.full_data())?;
            }
        }

        // --------------------- Write ARM7 program ---------------------
        self.align(&mut cursor, self.config.alignment.arm7, self.config.padding.arm7)?;
        context.arm7_offset = Some(cursor.position() as u32);
        context.arm7_autoload_callback = Some(self.arm7.autoload_callback());
        context.arm7_build_info_offset = Some(self.arm7.build_info_offset()).filter(|&offset| offset != 0);
        cursor.write_all(self.arm7.full_data())?;

        if !self.arm7_overlay_table.is_empty() {
            // --------------------- Write ARM7 overlay table ---------------------
            self.align(&mut cursor, self.config.alignment.arm7_overlay_table, self.config.padding.arm7_overlay_table)?;
            context.arm7_ovt_offset = Some(TableOffset {
                offset: cursor.position() as u32,
                size: (self.arm7_overlay_table.len() * size_of::<raw::Overlay>()) as u32,
            });
            let raw_table = self.arm7_overlay_table.build();
            cursor.write_all(raw_table.as_bytes())?;

            // --------------------- Write ARM7 overlays ---------------------
            for overlay in self.arm7_overlay_table.overlays() {
                self.align(&mut cursor, self.config.alignment.arm7_overlay, self.config.padding.arm7_overlays)?;
                let start = cursor.position() as u32;
                let end = start + overlay.full_data().len() as u32;
                file_allocs[overlay.file_id() as usize] = FileAlloc { start, end };

                cursor.write_all(overlay.full_data())?;
            }
        }

        // --------------------- Write file name table (FNT) ---------------------
        self.align(&mut cursor, self.config.alignment.file_name_table, self.config.padding.fnt)?;
        self.files.sort_for_fnt();
        let fnt = self.files.build_fnt()?.build()?;
        context.fnt_offset = Some(TableOffset { offset: cursor.position() as u32, size: fnt.len() as u32 });
        cursor.write_all(&fnt)?;

        // --------------------- Write file allocation table (FAT) placeholder ---------------------
        self.align(&mut cursor, self.config.alignment.file_allocation_table, self.config.padding.fat)?;
        context.fat_offset =
            Some(TableOffset { offset: cursor.position() as u32, size: (file_allocs.len() * size_of::<FileAlloc>()) as u32 });
        cursor.write_all(bytemuck::cast_slice(&file_allocs))?;

        // --------------------- Write banner ---------------------
        self.align(&mut cursor, self.config.alignment.banner, self.config.padding.banner)?;
        let banner = self.banner.build()?;
        context.banner_offset = Some(TableOffset { offset: cursor.position() as u32, size: banner.full_data().len() as u32 });
        cursor.write_all(banner.full_data())?;

        // --------------------- Write files ---------------------
        self.align(&mut cursor, self.config.alignment.file_image_block, self.config.padding.file_image)?;
        self.files.sort_for_rom();
        self.files.traverse_files(self.path_order.iter().map(|s| s.as_str()), |file, _| {
            // TODO: Rewrite traverse_files as an iterator so these errors can be returned
            self.align(&mut cursor, self.config.alignment.file, self.config.padding.file_image)
                .expect("failed to align after file");

            let contents = file.contents();
            let start = cursor.position() as u32;
            let end = start + contents.len() as u32;
            file_allocs[file.id() as usize] = FileAlloc { start, end };

            cursor.write_all(contents).expect("failed to write file contents");
        });

        // --------------------- Write DSi-specific parts ---------------------
        let dsi_layout = if let Some(dsi) = &self.dsi {
            self.align(&mut cursor, dsi.config().digest_sector_size, self.config.padding.file_image)?;
            let layout = dsi.layout(context.arm9_offset.unwrap(), cursor.position() as u32);

            // Hashtables are written by `Dsi::finalize` once the rest of the ROM is written
            self.write_padding_until(&mut cursor, layout.digest_sector_hashtable.offset, self.config.padding.rom)?;
            cursor.write_all(&vec![0; layout.digest_sector_hashtable.size as usize])?;
            self.write_padding_until(&mut cursor, layout.digest_block_hashtable.offset, self.config.padding.rom)?;
            cursor.write_all(&vec![0; layout.digest_block_hashtable.size as usize])?;
            self.write_padding_until(&mut cursor, layout.dsi_region_start, self.config.padding.rom)?;
            cursor.write_all(dsi.region_prefix())?;
            self.write_padding_until(&mut cursor, layout.arm9i.offset, self.config.padding.rom)?;
            cursor.write_all(dsi.arm9i())?;
            self.write_padding_until(&mut cursor, layout.arm7i.offset, self.config.padding.rom)?;
            cursor.write_all(dsi.arm7i())?;
            self.write_padding_until(&mut cursor, layout.rom_size_dsi, self.config.padding.rom)?;
            Some(layout)
        } else {
            None
        };

        // --------------------- Write multiboot signature ---------------------
        // Multiboot signature is placed "after" the ROM ends
        context.rom_size = Some(dsi_layout.map_or(cursor.position() as u32, |layout| layout.rom_size_ds));
        if let Some(multiboot_signature) = &self.multiboot_signature {
            cursor.write_all(bytemuck::bytes_of(multiboot_signature))?;
        }

        // --------------------- Write padding ---------------------
        let padded_rom_size = cursor.position().next_power_of_two().max(128 * 1024) as u32;
        self.align(&mut cursor, padded_rom_size, self.config.padding.rom)?;

        // --------------------- Update FAT ---------------------
        cursor.set_position(context.fat_offset.unwrap().offset as u64);
        cursor.write_all(bytemuck::cast_slice(&file_allocs))?;

        // --------------------- Write DSi digests and modcrypt ---------------------
        if let (Some(dsi), Some(layout)) = (&self.dsi, dsi_layout) {
            let arm7 = TableOffset { offset: context.arm7_offset.unwrap(), size: self.arm7.full_data().len() as u32 };
            context.dsi = Some(dsi.finalize(
                cursor.get_mut(),
                layout,
                &self.arm9,
                context.arm9_offset.unwrap(),
                arm7,
                context.banner_offset.unwrap(),
                self.header.original.gamecode.0,
                self.hmac_sha1.as_ref(),
                context.blowfish_key,
            )?);
        }

        // --------------------- Update header ---------------------
        cursor.set_position(context.header_offset.unwrap() as u64);
        let header = self.header.build(&context, &self)?;
        cursor.write_all(bytemuck::bytes_of(&header))?;

        Ok(raw::Rom::new(cursor.into_inner()))
    }

    fn write_padding_until(&self, cursor: &mut Cursor<Vec<u8>>, offset: u32, padding_value: u8) -> Result<(), RomBuildError> {
        let position = cursor.position() as u32;
        assert!(position <= offset, "cannot pad backwards from {position:#x} to {offset:#x}");
        cursor.write_all(&vec![padding_value; (offset - position) as usize])?;
        Ok(())
    }

    fn align(&self, cursor: &mut Cursor<Vec<u8>>, alignment: u32, padding_value: u8) -> Result<(), RomBuildError> {
        assert!(alignment.is_power_of_two(), "alignment must be a power of two");
        let mask = alignment - 1;
        let padding = (!cursor.position() as u32 + 1) & mask;
        for _ in 0..padding {
            cursor.write_all(&[padding_value])?;
        }
        Ok(())
    }

    /// Returns a reference to the header logo of this [`Rom`].
    pub fn header_logo(&self) -> &Logo {
        &self.header_logo
    }

    /// Returns a mutable reference to the header logo of this [`Rom`].
    pub fn header_logo_mut(&mut self) -> &mut Logo {
        &mut self.header_logo
    }

    /// Returns the DSi-specific parts of this [`Rom`], if it is DSi-enhanced or DSi-exclusive.
    pub fn dsi(&self) -> Option<&Dsi<'a>> {
        self.dsi.as_ref()
    }

    /// Returns a reference to the ARM9 program of this [`Rom`].
    pub fn arm9(&self) -> &Arm9<'a> {
        &self.arm9
    }

    /// Returns a mutable reference to the ARM9 program of this [`Rom`].
    pub fn arm9_mut(&mut self) -> &mut Arm9<'a> {
        &mut self.arm9
    }

    /// Returns a reference to the ARM9 overlay table of this [`Rom`].
    pub fn arm9_overlay_table(&self) -> &OverlayTable<'a> {
        &self.arm9_overlay_table
    }

    /// Returns a mutable reference to the ARM9 overlay table of this [`Rom`].
    pub fn arm9_overlay_table_mut(&mut self) -> &mut OverlayTable<'a> {
        &mut self.arm9_overlay_table
    }

    /// Returns a reference to the ARM9 overlays of this [`Rom`].
    pub fn arm9_overlays(&self) -> &[Overlay<'a>] {
        self.arm9_overlay_table.overlays()
    }

    /// Returns a mutable reference to the ARM9 overlays of this [`Rom`].
    pub fn arm9_overlays_mut(&mut self) -> &mut [Overlay<'a>] {
        self.arm9_overlay_table.overlays_mut()
    }

    /// Returns a reference to the ARM7 program of this [`Rom`].
    pub fn arm7(&self) -> &Arm7<'a> {
        &self.arm7
    }

    /// Returns a mutable reference to the ARM7 program of this [`Rom`].
    pub fn arm7_mut(&mut self) -> &mut Arm7<'a> {
        &mut self.arm7
    }

    /// Returns a reference to the ARM7 overlay table of this [`Rom`].
    pub fn arm7_overlay_table(&self) -> &OverlayTable<'a> {
        &self.arm7_overlay_table
    }

    /// Returns a mutable reference to the ARM7 overlay table of this [`Rom`].
    pub fn arm7_overlay_table_mut(&mut self) -> &mut OverlayTable<'a> {
        &mut self.arm7_overlay_table
    }

    /// Returns a reference to the ARM7 overlays of this [`Rom`].
    pub fn arm7_overlays(&self) -> &[Overlay<'a>] {
        self.arm7_overlay_table.overlays()
    }

    /// Returns a mutable reference to the ARM7 overlays of this [`Rom`].
    pub fn arm7_overlays_mut(&mut self) -> &mut [Overlay<'a>] {
        self.arm7_overlay_table.overlays_mut()
    }

    /// Returns a reference to the header of this [`Rom`].
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Returns a mutable reference to the header of this [`Rom`].
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Returns the [`RomConfig`] consisting of paths to extracted files.
    pub fn config(&self) -> &RomConfig {
        &self.config
    }

    /// Returns the [`MultibootSignature`] of this [`Rom`].
    pub fn multiboot_signature(&self) -> Option<&MultibootSignature> {
        self.multiboot_signature.as_ref()
    }
}

/// Build context, generated during [`Rom::build`] and later passed to [`Header::build`] to fill in the header.
#[derive(Default)]
pub struct BuildContext<'a> {
    /// Header offset.
    pub header_offset: Option<u32>,
    /// ARM9 program offset.
    pub arm9_offset: Option<u32>,
    /// ARM7 program offset.
    pub arm7_offset: Option<u32>,
    /// FNT offset.
    pub fnt_offset: Option<TableOffset>,
    /// FAT offset.
    pub fat_offset: Option<TableOffset>,
    /// ARM9 overlay table offset.
    pub arm9_ovt_offset: Option<TableOffset>,
    /// ARM7 overlay table offset.
    pub arm7_ovt_offset: Option<TableOffset>,
    /// Banner offset.
    pub banner_offset: Option<TableOffset>,
    /// Blowfish key.
    pub blowfish_key: Option<&'a BlowfishKey>,
    /// ARM9 autoload callback.
    pub arm9_autoload_callback: Option<u32>,
    /// ARM7 autoload callback.
    pub arm7_autoload_callback: Option<u32>,
    /// ARM9 build info offset.
    pub arm9_build_info_offset: Option<u32>,
    /// ARM7 build info offset.
    pub arm7_build_info_offset: Option<u32>,
    /// Total ROM size.
    pub rom_size: Option<u32>,
    /// Values for DSi-enhanced and DSi-exclusive ROMs.
    pub dsi: Option<DsiHeaderValues>,
}

/// Options for [`Rom::load`].
pub struct RomLoadOptions<'a> {
    /// Blowfish encryption key.
    pub key: Option<&'a BlowfishKey>,
    /// If true (default), compress ARM9 and overlays if they are configured with `compressed: true`.
    pub compress: bool,
    /// If true (default), encrypt ARM9 if it's configured with `encrypted: true`, and ARM9/overlays
    /// if they contain DS Protect.
    pub encrypt: bool,
    /// If true (default), load asset files.
    pub load_files: bool,
    /// If true (default), load the header and the header logo.
    pub load_header: bool,
    /// If true (default), load the banner.
    pub load_banner: bool,
    /// If true (default), load the multiboot signature.
    pub load_multiboot_signature: bool,
}

impl Default for RomLoadOptions<'_> {
    fn default() -> Self {
        Self {
            key: None,
            compress: true,
            encrypt: true,
            load_files: true,
            load_header: true,
            load_banner: true,
            load_multiboot_signature: true,
        }
    }
}
