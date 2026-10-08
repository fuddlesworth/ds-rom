use std::path::PathBuf;

use anyhow::Result;
use ds_rom::rom::{Rom, RomBuildError, raw};

use crate::common::RomsTest;

mod common;

/// Returns the DSi-enhanced and DSi-exclusive ROMs in the test directory.
fn dsi_roms(test: &RomsTest) -> Result<Vec<PathBuf>> {
    let mut roms = vec![];
    for path in test.roms()? {
        let path = path?;
        if path.file_name().unwrap().to_string_lossy().starts_with("build_") {
            continue;
        }
        if raw::Rom::from_file(&path)?.header()?.is_dsi() {
            roms.push(path);
        }
    }
    Ok(roms)
}

/// Building fails early if only one of the header's DSi section and the DSi area is present.
#[test]
fn rejects_incomplete_dsi() -> Result<()> {
    let test = RomsTest::new()?;
    for path in dsi_roms(&test)? {
        let raw_rom = raw::Rom::from_file(&path)?;

        let mut rom = Rom::extract(&raw_rom)?;
        rom.header_mut().dsi = None;
        let result = rom.build(Some(&test.key));
        assert!(matches!(result, Err(RomBuildError::DsiIncomplete { .. })), "{}", path.display());
    }
    Ok(())
}
