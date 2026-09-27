use std::{
    cmp::Ordering,
    fmt::Display,
    mem::{align_of, size_of},
};

use bytemuck::{Pod, PodCastError, Zeroable};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::RawBuildInfoError;

/// An entry in the autoload list.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Zeroable, Pod, Deserialize, Serialize)]
pub struct AutoloadInfoEntry {
    /// Base address of the autoload module.
    pub base_address: u32,
    /// Size of the module's initialized area.
    pub code_size: u32,
    /// Size of the module's uninitialized area.
    pub bss_size: u32,
}

/// An entry in the autoload list of DSi-enhanced and DSi-exclusive titles. The TWL-SDK adds the address of the static
/// initializer table to each entry.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroable, Pod)]
pub struct TwlAutoloadInfoEntry {
    /// Base address of the autoload module.
    pub base_address: u32,
    /// Size of the module's initialized area.
    pub code_size: u32,
    /// Start address of the module's static initializer table.
    pub sinit_start: u32,
    /// Size of the module's uninitialized area.
    pub bss_size: u32,
}

/// Autoload kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum AutoloadKind {
    /// Instruction TCM (Tightly Coupled Memory). Mainly used to make functions have fast and predictable load times.
    Itcm,
    /// Data TCM (Tightly Coupled Memory). Mainly used to make data have fast and predictable access times.
    Dtcm,
    /// Other autoload block of unknown purpose.
    Unknown(u32),
    /// Autoload block of the ARM9i program in DSi-enhanced and DSi-exclusive titles, only loaded in DSi mode.
    Ltd(u32),
}

impl PartialOrd for AutoloadKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AutoloadKind {
    fn cmp(&self, other: &Self) -> Ordering {
        // ITCM < DTCM < Unknown < Ltd
        match (self, other) {
            (_, _) if self == other => Ordering::Equal,
            (AutoloadKind::Itcm, _) => Ordering::Less,
            (_, AutoloadKind::Itcm) => Ordering::Greater,
            (AutoloadKind::Dtcm, _) => Ordering::Less,
            (_, AutoloadKind::Dtcm) => Ordering::Greater,
            (AutoloadKind::Unknown(a), AutoloadKind::Unknown(b)) => a.cmp(b),
            (AutoloadKind::Unknown(_), AutoloadKind::Ltd(_)) => Ordering::Less,
            (AutoloadKind::Ltd(_), AutoloadKind::Unknown(_)) => Ordering::Greater,
            (AutoloadKind::Ltd(a), AutoloadKind::Ltd(b)) => a.cmp(b),
        }
    }
}

/// Info about an autoload block.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct AutoloadInfo {
    #[serde(flatten)]
    /// Entry in the autoload list.
    pub list_entry: AutoloadInfoEntry,
    /// The kind of autoload block.
    pub kind: AutoloadKind,
    /// Start address of the static initializer table, only present in the TWL-SDK autoload list format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sinit_start: Option<u32>,
}

/// Errors related to [`AutoloadInfo`].
#[derive(Debug, Snafu)]
pub enum RawAutoloadInfoError {
    /// See [`RawBuildInfoError`].
    #[snafu(transparent)]
    RawBuildInfo {
        /// Source error.
        source: RawBuildInfoError,
    },
    /// Occurs when the input is not evenly divisible into a slice of autoload list entries.
    #[snafu(display("autoload infos must be a multiple of {entry_size} bytes:\n{backtrace}"))]
    InvalidSize {
        /// Size of one autoload list entry.
        entry_size: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input is less aligned than [`AutoloadInfo`].
    #[snafu(display("expected {expected}-alignment for autoload infos but got {actual}-alignment:\n{backtrace}"))]
    Misaligned {
        /// Expected alignment.
        expected: usize,
        /// Actual input alignment.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

fn borrow_entries<T: Pod>(data: &'_ [u8]) -> Result<&'_ [T], RawAutoloadInfoError> {
    let entry_size = size_of::<T>();
    if !data.len().is_multiple_of(entry_size) {
        return InvalidSizeSnafu { entry_size }.fail();
    }
    let addr = data as *const [u8] as *const () as usize;
    match bytemuck::try_cast_slice(data) {
        Ok(entries) => Ok(entries),
        Err(PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
            MisalignedSnafu { expected: align_of::<T>(), actual: 1usize << addr.trailing_zeros() }.fail()
        }
        Err(PodCastError::AlignmentMismatch) => panic!(),
        Err(PodCastError::OutputSliceWouldHaveSlop) => panic!(),
        Err(PodCastError::SizeMismatch) => unreachable!(),
    }
}

impl AutoloadInfoEntry {
    /// Reinterprets a `&[u8]` as a slice of [`AutoloadInfoEntry`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input has the wrong size or alignment.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawAutoloadInfoError> {
        borrow_entries(data)
    }
}

impl TwlAutoloadInfoEntry {
    /// Reinterprets a `&[u8]` as a slice of [`TwlAutoloadInfoEntry`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the input has the wrong size or alignment.
    pub fn borrow_from_slice(data: &'_ [u8]) -> Result<&'_ [Self], RawAutoloadInfoError> {
        borrow_entries(data)
    }
}

impl AutoloadInfo {
    /// Creates a new [`AutoloadInfo`] from an [`AutoloadInfoEntry`].
    pub fn new(list_entry: AutoloadInfoEntry, index: u32) -> Self {
        let kind = match list_entry.base_address {
            0x1ff8000 => AutoloadKind::Itcm,
            // 0x2fe0000 is used by DSi-enhanced titles
            0x27e0000 | 0x27c0000 | 0x23c0000 | 0x2fe0000 => AutoloadKind::Dtcm,
            _ => AutoloadKind::Unknown(index),
        };

        Self { list_entry, kind, sinit_start: None }
    }

    /// Creates a new [`AutoloadInfo`] from a [`TwlAutoloadInfoEntry`].
    pub fn new_twl(twl_entry: TwlAutoloadInfoEntry, index: u32) -> Self {
        let TwlAutoloadInfoEntry { base_address, code_size, sinit_start, bss_size } = twl_entry;
        let list_entry = AutoloadInfoEntry { base_address, code_size, bss_size };
        Self { sinit_start: Some(sinit_start), ..Self::new(list_entry, index) }
    }

    /// Returns the raw bytes of this autoload's list entry, in the TWL-SDK format if [`Self::sinit_start`] is present.
    pub fn entry_bytes(&self) -> Vec<u8> {
        let AutoloadInfoEntry { base_address, code_size, bss_size } = self.list_entry;
        match self.sinit_start {
            Some(sinit_start) => {
                bytemuck::bytes_of(&TwlAutoloadInfoEntry { base_address, code_size, sinit_start, bss_size }).to_vec()
            }
            None => bytemuck::bytes_of(&self.list_entry).to_vec(),
        }
    }

    /// Returns the index of this [`AutoloadInfo`].
    pub fn base_address(&self) -> u32 {
        self.list_entry.base_address
    }

    /// Returns the code size of this [`AutoloadInfo`].
    pub fn code_size(&self) -> u32 {
        self.list_entry.code_size
    }

    /// Returns the size of the uninitialized data of this [`AutoloadInfo`].
    pub fn bss_size(&self) -> u32 {
        self.list_entry.bss_size
    }

    /// Returns the kind of this [`AutoloadInfo`].
    pub fn kind(&self) -> AutoloadKind {
        self.kind
    }

    /// Returns the entry of this [`AutoloadInfo`].
    pub fn entry(&self) -> &AutoloadInfoEntry {
        &self.list_entry
    }

    /// Creates a [`DisplayAutoloadInfo`] which implements [`Display`].
    pub fn display(&self, indent: usize) -> DisplayAutoloadInfo<'_> {
        DisplayAutoloadInfo { info: self, indent }
    }
}

/// Can be used to display values inside [`AutoloadInfo`].
pub struct DisplayAutoloadInfo<'a> {
    info: &'a AutoloadInfo,
    indent: usize,
}

impl Display for DisplayAutoloadInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        let info = &self.info;
        writeln!(f, "{i}Type .......... : {}", info.kind)?;
        writeln!(f, "{i}Base address .. : {:#x}", info.list_entry.base_address)?;
        writeln!(f, "{i}Code size ..... : {:#x}", info.list_entry.code_size)?;
        writeln!(f, "{i}.bss size ..... : {:#x}", info.list_entry.bss_size)?;
        if let Some(sinit_start) = info.sinit_start {
            writeln!(f, "{i}.sinit start .. : {sinit_start:#x}")?;
        }
        Ok(())
    }
}

impl Display for AutoloadKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoloadKind::Itcm => write!(f, "ITCM"),
            AutoloadKind::Dtcm => write!(f, "DTCM"),
            AutoloadKind::Unknown(index) => write!(f, "Unknown({index})"),
            AutoloadKind::Ltd(index) => write!(f, "Ltd({index})"),
        }
    }
}
