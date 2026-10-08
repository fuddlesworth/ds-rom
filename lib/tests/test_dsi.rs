use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use ds_rom::{
    crypto::{blowfish::BlowfishKey, hmac_sha1::HmacSha1, modcrypt::Modcrypt},
    rom::{Rom, RomBuildError, RomLoadOptions, raw},
};

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

/// Everything the digest tables and SHA1-HMACs of a DSi ROM should hash, recomputed here from the ROM itself so that a
/// build cannot pass by copying stale values out of the ROM it was extracted from.
#[derive(Debug, PartialEq, Eq)]
struct DsiHashes {
    sector_hashtable: Vec<u8>,
    block_hashtable: Vec<u8>,
    digest_master: [u8; 20],
    arm9_with_secure_area: [u8; 20],
    arm9: [u8; 20],
    arm7: [u8; 20],
    banner: [u8; 20],
    arm9i: [u8; 20],
    arm7i: [u8; 20],
}

/// Returns the digest form of `rom`, which is what the DSi hashes: the ARM9 secure area encrypted and the modcrypt areas
/// decrypted.
fn digest_form(rom: &[u8], key: &BlowfishKey) -> Result<Vec<u8>> {
    let raw_rom = raw::Rom::new(rom);
    let header = raw_rom.header()?;
    let mut form = rom.to_vec();

    let arm9 = raw_rom.arm9()?;
    if !arm9.is_encrypted() {
        let encrypted = arm9.encrypted_secure_area(key, header.gamecode.to_le_u32());
        let start = header.arm9.offset as usize;
        form[start..start + encrypted.len()].copy_from_slice(&encrypted);
    }

    let modcrypt = Modcrypt::new_retail(header.gamecode.0, &header.sha1_hmac_arm9i);
    for (area, counter) in
        [(header.modcrypt_area_1, header.sha1_hmac_arm9_with_secure_area), (header.modcrypt_area_2, header.sha1_hmac_arm7)]
    {
        let start = area.offset as usize;
        modcrypt.apply(&mut form[start..start + area.size as usize], &counter);
    }
    Ok(form)
}

fn compute_hashes(rom: &[u8], key: &BlowfishKey) -> Result<DsiHashes> {
    let raw_rom = raw::Rom::new(rom);
    let header = raw_rom.header()?;
    let mut plain_arm9 = raw_rom.arm9()?;
    plain_arm9.decompress()?;
    let hmac = HmacSha1::new(plain_arm9.hmac_sha1_key()?.ok_or_else(|| anyhow!("no HMAC-SHA1 key"))?);

    let form = digest_form(rom, key)?;
    let sector_size = header.digest_sector_size as usize;
    let per_block = header.digest_sector_count as usize;
    let range = |offset: u32, size: u32| offset as usize..offset as usize + size as usize;

    // Sector hashes over the DS area followed by the DSi area, padded with zeroed entries up to a whole block
    let mut sector_hashtable = vec![];
    for area in [header.digest_ds_area, header.digest_dsi_area] {
        for sector in form[range(area.offset, area.size)].chunks(sector_size) {
            sector_hashtable.extend_from_slice(&hmac.compute(sector));
        }
    }
    let num_blocks = (sector_hashtable.len() / 20).div_ceil(per_block);
    sector_hashtable.resize(num_blocks * per_block * 20, 0);

    let mut block_hashtable = vec![];
    for block in sector_hashtable.chunks(per_block * 20) {
        block_hashtable.extend_from_slice(&hmac.compute(block));
    }

    let arm9 = &form[range(header.arm9.offset, header.arm9.size)];
    Ok(DsiHashes {
        digest_master: hmac.compute(&block_hashtable),
        sector_hashtable,
        block_hashtable,
        arm9_with_secure_area: hmac.compute(arm9),
        arm9: hmac.compute(&arm9[0x4000..]),
        arm7: hmac.compute(&form[range(header.arm7.offset, header.arm7.size)]),
        banner: hmac.compute(&form[range(header.banner_offset, header.banner_size)]),
        arm9i: hmac.compute(&form[range(header.arm9i.offset, header.arm9i.size)]),
        arm7i: hmac.compute(&form[range(header.arm7i.offset, header.arm7i.size)]),
    })
}

/// Checks that every hash a DSi ROM stores describes its own contents.
fn assert_self_consistent(rom: &[u8], key: &BlowfishKey, label: &str) -> Result<DsiHashes> {
    let hashes = compute_hashes(rom, key)?;
    let raw_rom = raw::Rom::new(rom);
    let header = raw_rom.header()?;

    let stored = |table: raw::TableOffset| &rom[table.offset as usize..(table.offset + table.size) as usize];
    assert_eq!(stored(header.digest_sector_hashtable), hashes.sector_hashtable, "{label}: digest sector hashtable");
    assert_eq!(stored(header.digest_block_hashtable), hashes.block_hashtable, "{label}: digest block hashtable");
    assert_eq!(header.sha1_hmac_digest, hashes.digest_master, "{label}: digest master hash");
    assert_eq!(header.sha1_hmac_arm9_with_secure_area, hashes.arm9_with_secure_area, "{label}: ARM9 hash with secure area");
    assert_eq!(header.sha1_hmac_arm9, hashes.arm9, "{label}: ARM9 hash");
    assert_eq!(header.sha1_hmac_arm7, hashes.arm7, "{label}: ARM7 hash");
    assert_eq!(header.sha1_hmac_banner, hashes.banner, "{label}: banner hash");
    assert_eq!(header.sha1_hmac_arm9i, hashes.arm9i, "{label}: ARM9i hash");
    assert_eq!(header.sha1_hmac_arm7i, hashes.arm7i, "{label}: ARM7i hash");
    Ok(hashes)
}

/// Builds the extracted ROM, with the Blowfish key or with the stored secure area values.
fn build(extract_path: &Path, key: Option<&BlowfishKey>) -> Result<Vec<u8>> {
    let rom = Rom::load(extract_path.join("config.yaml"), RomLoadOptions { key, ..Default::default() })?;
    Ok(rom.build(key)?.data().to_vec())
}

/// Flips a bit in the middle of a file, leaving its size alone.
fn flip_a_bit(path: &Path) -> Result<()> {
    let mut data = fs::read(path)?;
    assert!(!data.is_empty(), "{} is empty", path.display());
    let middle = data.len() / 2;
    data[middle] ^= 0x01;
    fs::write(path, data)?;
    Ok(())
}

/// Returns the first file in `dir` larger than 16 bytes, searching subdirectories in order.
fn find_asset(dir: &Path) -> Result<Option<PathBuf>> {
    let mut entries = fs::read_dir(dir)?.map(|entry| Ok(entry?.path())).collect::<Result<Vec<_>>>()?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if let Some(asset) = find_asset(&path)? {
                return Ok(Some(asset));
            }
        } else if fs::metadata(&path)?.len() > 16 {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Rebuilding a DSi ROM recomputes every digest and SHA1-HMAC from its contents. Adapted from AetiasHax/ds-rom#30 by
/// Thomas Macmillan.
#[test]
fn test_dsi_hashes_are_regenerated() -> Result<()> {
    let test = RomsTest::new()?;
    for path in dsi_roms(&test)? {
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        let original = fs::read(&path)?;
        let raw_rom = raw::Rom::new(original.as_slice());

        // The extract directory must not end in `.nds`, or the ROM iterator would pick it up as a ROM
        let base_name = path.file_stem().unwrap().to_string_lossy();
        let extract_path = test.roms_dir.join(format!("dsi_test_{base_name}"));
        if extract_path.exists() {
            fs::remove_dir_all(&extract_path)?;
        }
        Rom::extract(&raw_rom)?.save(&extract_path, Some(&test.key))?;

        // An unmodified rebuild must match the original, which proves the recomputed tables and hashes are right and not
        // merely self-consistent
        for key in [Some(&test.key), None] {
            let rebuilt = build(&extract_path, key)?;
            assert!(rebuilt == original, "{file_name}: unmodified rebuild did not match, Blowfish key: {}", key.is_some());
        }
        let before = assert_self_consistent(&original, &test.key, "unmodified")?;

        // Change the DS area, the banner and the ARM9i, and check that the hashes follow the new contents. Changing the
        // ARM9i also changes the modcrypt key, which is derived from the ARM9i hash
        let ltd_autoload = extract_path.join("dsi/ltd_autoload_0.bin");
        let arm9i = if ltd_autoload.exists() {
            ltd_autoload
        } else {
            extract_path.join("dsi/arm9i.bin")
        };
        flip_a_bit(&arm9i)?;

        let banner_config = extract_path.join("banner/banner.yaml");
        let banner_yaml = fs::read_to_string(&banner_config)?;
        assert!(banner_yaml.contains("Nintendo"), "banner title not found");
        fs::write(&banner_config, banner_yaml.replacen("Nintendo", "Nintendk", 1))?;

        let asset = find_asset(&extract_path.join("files"))?.ok_or_else(|| anyhow!("no asset file to modify"))?;
        flip_a_bit(&asset)?;

        // The ARM9 is unchanged, so building with the stored secure area values must give the same ROM as with the key
        let modified = build(&extract_path, Some(&test.key))?;
        assert_eq!(modified.len(), original.len(), "{file_name}: modified ROM changed size");
        assert!(modified != original, "{file_name}: modified ROM is identical to the original");
        let after = assert_self_consistent(&modified, &test.key, "modified")?;

        // Every hash which covers changed data must have changed. If one was copied from the original header instead of
        // recomputed, the rebuilt ROM would be silently corrupt
        assert_ne!(before.digest_master, after.digest_master, "digest master hash did not change");
        assert_ne!(before.sector_hashtable, after.sector_hashtable, "sector hashtable did not change");
        assert_ne!(before.block_hashtable, after.block_hashtable, "block hashtable did not change");
        assert_ne!(before.arm9i, after.arm9i, "ARM9i hash did not change");
        assert_ne!(before.banner, after.banner, "banner hash did not change");

        // The ARM9 outside the secure area, the ARM7 and the ARM7i are unchanged, so their hashes must be too. The secure area
        // holds the LTD module parameters, which change with the size of the compressed ARM9i
        assert_eq!(before.arm9, after.arm9, "ARM9 hash changed");
        assert_eq!(before.arm7, after.arm7, "ARM7 hash changed");
        assert_eq!(before.arm7i, after.arm7i, "ARM7i hash changed");

        // A new modcrypt key means that the encrypted ARM9i differs by far more than one bit
        let header = *raw::Rom::new(modified.as_slice()).header()?;
        let area = header.modcrypt_area_1;
        let range = area.offset as usize..(area.offset + area.size) as usize;
        let differing = original[range.clone()].iter().zip(&modified[range]).filter(|(a, b)| a != b).count();
        assert!(differing > area.size as usize / 4, "modcrypt area barely changed, its key was probably not derived again");

        fs::remove_dir_all(&extract_path)?;
    }
    Ok(())
}
