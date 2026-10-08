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

/// Layout of the entries in an autoload list. Which one a program uses depends on its SDK.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AutoloadInfoLayout {
    /// 12-byte entries, see [`AutoloadInfoEntry`]. Used by the NITRO-SDK.
    Basic,
    /// 16-byte entries, see [`TwlAutoloadInfoEntry`]. Used by the TWL-SDK, in DSi-enhanced and DSi-exclusive titles.
    Twl,
}

impl AutoloadInfoLayout {
    /// All layouts, in the order they are tried when detecting the layout of an autoload list.
    pub const ALL: [Self; 2] = [Self::Basic, Self::Twl];

    /// Size of one autoload list entry in this layout.
    pub fn entry_size(self) -> usize {
        match self {
            Self::Basic => size_of::<AutoloadInfoEntry>(),
            Self::Twl => size_of::<TwlAutoloadInfoEntry>(),
        }
    }

    /// Detects the layout of an autoload list. `blocks_size` is the combined size of the autoload blocks, which the code
    /// sizes of the entries should add up to. This tells the layouts apart, as a list in one layout can otherwise be
    /// misparsed in the other, for example a 48-byte list of three 16-byte or four 12-byte entries.
    ///
    /// If no layout's code sizes add up to `blocks_size`, the only layout whose entries are all plausible is used.
    ///
    /// # Errors
    ///
    /// This function will return an error if `data` is not a whole number of entries in any layout, or if no layout or
    /// more than one layout is plausible and no layout's code sizes add up to `blocks_size`.
    pub fn detect(data: &[u8], blocks_size: u32) -> Result<Self, RawAutoloadInfoError> {
        let candidates = Self::ALL
            .into_iter()
            .filter(|layout| data.len().is_multiple_of(layout.entry_size()))
            .map(|layout| (layout, AutoloadInfo::parse_list(data, layout)))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return NoLayoutSizeSnafu { size: data.len() }.fail();
        }

        // The code sizes adding up to the size of the autoload blocks is a strong signal that the layout is correct
        let code_sizes = |infos: &[AutoloadInfo]| infos.iter().map(|info| info.code_size() as u64).sum::<u64>();
        if let Some((layout, _)) = candidates.iter().find(|(_, infos)| code_sizes(infos) == blocks_size as u64) {
            return Ok(*layout);
        }

        // The autoload blocks are not packed as expected, so fall back to the only plausible layout. If several are
        // plausible, picking one could silently misparse the list
        let plausible = candidates
            .iter()
            .filter(|(_, infos)| infos.iter().all(|info| info.list_entry.is_plausible()))
            .map(|(layout, _)| *layout)
            .collect::<Vec<_>>();
        match plausible.as_slice() {
            [layout] => {
                log::warn!(
                    "Autoload block sizes don't add up to {blocks_size:#x} bytes in any layout, assuming the {layout} layout"
                );
                Ok(*layout)
            }
            [] => NoMatchingLayoutSnafu { size: data.len(), expected_blocks_size: blocks_size }.fail(),
            _ => AmbiguousLayoutSnafu { size: data.len(), count: plausible.len(), expected_blocks_size: blocks_size }.fail(),
        }
    }
}

impl Display for AutoloadInfoLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic ({}-byte entries)", self.entry_size()),
            Self::Twl => write!(f, "TWL-SDK ({}-byte entries)", self.entry_size()),
        }
    }
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
    /// Occurs when the input cannot be divided into autoload list entries of any layout.
    #[snafu(display(
        "autoload infos are {size} bytes, which is not a multiple of 12 (basic layout) or 16 (TWL-SDK layout):\n{backtrace}"
    ))]
    NoLayoutSize {
        /// Size of the input.
        size: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the input divides evenly into entries but no layout gives a plausible autoload list.
    #[snafu(display(
        "autoload infos of {size} bytes do not parse into a plausible autoload list in any layout, expected the code sizes \
         to add up to {expected_blocks_size:#x} bytes of autoload blocks:\n{backtrace}"
    ))]
    NoMatchingLayout {
        /// Size of the input.
        size: usize,
        /// Combined size of the autoload blocks, which the entries' code sizes should add up to.
        expected_blocks_size: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when more than one layout parses plausibly and the autoload blocks don't tell them apart.
    #[snafu(display(
        "autoload infos of {size} bytes are ambiguous: they parse plausibly in {count} layouts but no layout's code sizes \
         add up to {expected_blocks_size:#x} bytes of autoload blocks:\n{backtrace}"
    ))]
    AmbiguousLayout {
        /// Size of the input.
        size: usize,
        /// Number of layouts that parsed plausibly.
        count: usize,
        /// Combined size of the autoload blocks, which the entries' code sizes should add up to.
        expected_blocks_size: u32,
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

impl AutoloadInfoEntry {
    /// Returns whether this entry could plausibly describe an autoload module. Used to rule out layouts when the autoload
    /// blocks don't tell them apart.
    fn is_plausible(&self) -> bool {
        // Every memory region an autoload can be loaded into starts at 0x01000000 (ITCM) or above, and no module comes close
        // to filling the DSi's 16MB of main RAM
        self.base_address >= 0x01000000 && self.code_size < 0x01000000 && self.bss_size < 0x01000000
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

    /// Parses an autoload list in the given layout, see [`AutoloadInfoLayout::detect`]. Trailing bytes which don't make up a
    /// whole entry are ignored.
    pub fn parse_list(data: &[u8], layout: AutoloadInfoLayout) -> Vec<Self> {
        let entries = data.chunks_exact(layout.entry_size()).enumerate();
        match layout {
            AutoloadInfoLayout::Basic => {
                entries.map(|(index, entry)| Self::new(bytemuck::pod_read_unaligned(entry), index as u32)).collect()
            }
            AutoloadInfoLayout::Twl => {
                entries.map(|(index, entry)| Self::new_twl(bytemuck::pod_read_unaligned(entry), index as u32)).collect()
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Autoload list of Pokémon Black Version 2, which uses the TWL-SDK layout.
    const TWL: [u8; 64] = [
        0x00, 0x80, 0xff, 0x01, 0xa0, 0x13, 0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0xfe, 0x02, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x02, 0x20, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x40, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x80, 0x89, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x80, 0x89, 0x06, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Autoload list in the basic layout, with an ITCM and a DTCM block.
    const BASIC: [u8; 24] = [
        0x00, 0x80, 0xff, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x7e, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    ];

    fn parse(data: &[u8], blocks_size: u32) -> Result<Vec<AutoloadInfo>, RawAutoloadInfoError> {
        Ok(AutoloadInfo::parse_list(data, AutoloadInfoLayout::detect(data, blocks_size)?))
    }

    #[test]
    fn parses_twl_layout() {
        let infos = parse(&TWL, 0x1480).unwrap();
        assert_eq!(infos.len(), 4);
        assert_eq!(infos[0].list_entry, AutoloadInfoEntry { base_address: 0x01ff8000, code_size: 0x13a0, bss_size: 0 });
        assert_eq!(infos[0].sinit_start, Some(0x01ff8000));
        assert_eq!(infos[0].kind, AutoloadKind::Itcm);
        assert_eq!(infos[1].base_address(), 0x02fe0000);
        assert_eq!(infos[1].bss_size(), 0x20);
        assert_eq!(infos[3].base_address(), 0x06898000);
    }

    #[test]
    fn parses_basic_layout() {
        let infos = parse(&BASIC, 0x3000).unwrap();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].list_entry, AutoloadInfoEntry { base_address: 0x01ff8000, code_size: 0x2000, bss_size: 0 });
        assert_eq!(infos[1].list_entry, AutoloadInfoEntry { base_address: 0x027e0000, code_size: 0x1000, bss_size: 0x400 });
        assert!(infos.iter().all(|info| info.sinit_start.is_none()));
    }

    /// A list of three TWL-SDK entries is 48 bytes, which also divides into four basic entries. The size of the autoload
    /// blocks has to break the tie.
    #[test]
    fn tells_ambiguous_sizes_apart() {
        let infos = parse(&TWL[..48], 0x1460).unwrap();
        assert_eq!(infos.len(), 3);
        assert_eq!(infos[2].base_address(), 0x02400000);
        assert!(infos.iter().all(|info| info.sinit_start.is_some()));
    }

    #[test]
    fn round_trips_both_layouts() {
        for (data, blocks_size) in [(&TWL[..], 0x1480), (&BASIC[..], 0x3000)] {
            let infos = parse(data, blocks_size).unwrap();
            let bytes = infos.iter().flat_map(|info| info.entry_bytes()).collect::<Vec<_>>();
            assert_eq!(bytes, data);
        }
    }

    #[test]
    fn rejects_sizes_that_are_no_layout() {
        let error = parse(&TWL[..20], 0x1480).unwrap_err();
        assert!(matches!(error, RawAutoloadInfoError::NoLayoutSize { .. }));
    }

    /// When no layout's code sizes add up to the autoload blocks but exactly one layout parses plausibly, that layout is
    /// used. The 64-byte list only divides into TWL-SDK entries.
    #[test]
    fn falls_back_to_the_only_plausible_layout() {
        assert_eq!(parse(&TWL, 0x9999).unwrap(), parse(&TWL, 0x1480).unwrap());
    }

    /// The only layout is rejected if its entries are implausible and its code sizes don't add up.
    #[test]
    fn rejects_the_only_layout_when_implausible() {
        let error = parse(&[0u8; 12], 0x100).unwrap_err();
        assert!(matches!(error, RawAutoloadInfoError::NoMatchingLayout { .. }));
    }
}
