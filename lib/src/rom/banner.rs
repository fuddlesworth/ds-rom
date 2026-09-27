use std::{
    fs::File,
    io::{self, BufReader, BufWriter},
    path::{Path, PathBuf},
};

use image::{GenericImageView, ImageError, ImageReader, Rgba, RgbaImage};
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use super::{
    ImageSize,
    raw::{self, BannerBitmap, BannerPalette, BannerVersion, Language},
};
use crate::{crc::CRC_16_MODBUS, str::Unicode16Array};

/// ROM banner.
#[derive(Serialize, Deserialize, Default)]
pub struct Banner {
    version: BannerVersion,
    /// Game title in different languages.
    pub title: BannerTitle,
    /// Icon to show on the home screen.
    pub images: BannerImages,
    /// Keyframes for animated icons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyframes: Option<Vec<BannerKeyframe>>,
}

/// Errors related to [`Banner`].
#[derive(Debug, Snafu)]
pub enum BannerError {
    /// See [`BannerImageError`].
    #[snafu(transparent)]
    BannerFile {
        /// Source error.
        source: BannerImageError,
    },
    /// Occurs when trying to build a banner to place in the ROM, but there were too many keyframes.
    #[snafu(display("maximum keyframe count is {max} but got {actual}:\n{backtrace}"))]
    TooManyKeyframes {
        /// Max allowed amount.
        max: usize,
        /// Actual amount.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when trying to build a banner to place in the ROM, but the version is not yet supported by this library.
    #[snafu(display("maximum supported banner version is currently {max} but got {actual}:\n{backtrace}"))]
    VersionNotSupported {
        /// Max supported version.
        max: BannerVersion,
        /// Actual version.
        actual: BannerVersion,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl Banner {
    fn load_title(banner: &raw::Banner, version: BannerVersion, language: Language) -> Option<String> {
        if version.supports_language(language) {
            banner.title(language).map(|title| title.to_string())
        } else {
            None
        }
    }

    /// Loads from a raw banner.
    pub fn load_raw(banner: &raw::Banner) -> Self {
        let version = banner.version();
        Self {
            version,
            title: BannerTitle {
                japanese: Self::load_title(banner, version, Language::Japanese).unwrap(),
                english: Self::load_title(banner, version, Language::English).unwrap(),
                french: Self::load_title(banner, version, Language::French).unwrap(),
                german: Self::load_title(banner, version, Language::German).unwrap(),
                italian: Self::load_title(banner, version, Language::Italian).unwrap(),
                spanish: Self::load_title(banner, version, Language::Spanish).unwrap(),
                chinese: Self::load_title(banner, version, Language::Chinese),
                korean: Self::load_title(banner, version, Language::Korean),
            },
            images: BannerImages::from_raw(banner),
            keyframes: None,
        }
    }

    fn crc(&self, banner: &mut raw::Banner, version: BannerVersion) {
        if self.version >= version {
            *banner.crc_mut(version.crc_index()) = CRC_16_MODBUS.checksum(&banner.full_data()[version.crc_range()]);
        }
    }

    /// Builds a raw banner to place in a ROM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the banner version is not yet supported by this library, or there are too many
    /// keyframes.
    pub fn build(&self) -> Result<raw::Banner<'_>, BannerError> {
        // TODO: Increase max version to Animated
        // The challenge is to convert the animated icon to indexed bitmaps. Each bitmap can use any of the 8 palettes at any
        // given time according to the keyframes. This means that to convert the PNG animation frames to indexed bitmaps, we
        // may need more than 8 PNG files if a palette is reused on multiple bitmaps. Then we have to deduplicate indexed
        // bitmaps with precisely the same indexes. Not very efficient, but it may be our only option for modern image formats.
        // Animated icons can only be built from a raw animation file, see `BannerImages::animation`
        if self.version > BannerVersion::Korea && self.images.animation.is_none() {
            return VersionNotSupportedSnafu { max: BannerVersion::Korea, actual: self.version }.fail();
        }

        let mut banner = raw::Banner::new(self.version);
        self.title.copy_to_banner(&mut banner);

        *banner.bitmap_mut() = self.images.bitmap;
        *banner.palette_mut() = self.images.palette;

        if let (Some(animation), Some(raw_animation)) = (&self.images.animation, banner.animation_mut()) {
            *raw_animation = **animation;
        }

        if let Some(keyframes) = &self.keyframes {
            if keyframes.len() > 64 {
                TooManyKeyframesSnafu { max: 64usize, actual: keyframes.len() }.fail()?;
            }

            let animation = banner.animation_mut().unwrap();
            for i in 0..keyframes.len() {
                animation.keyframes[i] = keyframes[i].build();
            }
            for i in keyframes.len()..64 {
                animation.keyframes[i] = raw::BannerKeyframe::new();
            }
        }

        self.crc(&mut banner, BannerVersion::Original);
        self.crc(&mut banner, BannerVersion::China);
        self.crc(&mut banner, BannerVersion::Korea);
        self.crc(&mut banner, BannerVersion::Animated);

        Ok(banner)
    }
}

/// Icon for the [`Banner`].
#[derive(Default, Serialize, Deserialize)]
pub struct BannerImages {
    /// Main bitmap.
    #[serde(skip)]
    pub bitmap: BannerBitmap,
    /// Main palette.
    #[serde(skip)]
    pub palette: BannerPalette,
    /// Bitmaps for animated icon.
    #[serde(skip)]
    pub animation_bitmaps: Option<Box<[BannerBitmap]>>,
    /// Palettes for animated icon
    #[serde(skip)]
    pub animation_palettes: Option<Box<[BannerPalette]>>,
    /// Raw animated icon of DSi banners, stored as-is until the bitmaps and palettes can be converted to PNG files.
    #[serde(skip)]
    pub animation: Option<Box<raw::BannerAnimation>>,

    /// Path to bitmap PNG.
    pub bitmap_path: PathBuf,
    /// Path to palette PNG.
    pub palette_path: PathBuf,
    /// Path to raw animated icon, see [`Self::animation`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub animation_path: Option<PathBuf>,
}

/// Errors related to [`BannerImages`].
#[derive(Debug, Snafu)]
pub enum BannerImageError {
    /// See [`io::Error`].
    #[snafu(transparent)]
    Io {
        /// Error source.
        source: io::Error,
    },
    /// See [`ImageError`].
    #[snafu(transparent)]
    Image {
        /// Source error.
        source: ImageError,
    },
    /// See [`png::EncodingError`].
    #[snafu(transparent)]
    PngEncoding {
        /// Source error.
        source: png::EncodingError,
    },
    /// See [`png::DecodingError`].
    #[snafu(transparent)]
    PngDecoding {
        /// Source error.
        source: png::DecodingError,
    },
    /// Occurs when loading a banner image with the wrong size.
    #[snafu(display("banner icon must be {expected} pixels but got {actual} pixels:\n{backtrace}"))]
    WrongSize {
        /// Expected size.
        expected: ImageSize,
        /// Actual input size.
        actual: ImageSize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when the bitmap has a pixel not present in the palette.
    #[snafu(display("banner icon {bitmap:?} contains a pixel at {x},{y} which is not present in the palette:\n{backtrace}"))]
    InvalidPixel {
        /// Path to the bitmap.
        bitmap: PathBuf,
        /// X coordinate.
        x: u32,
        /// Y coordinate.
        y: u32,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
    /// Occurs when loading a raw animated icon with the wrong size.
    #[snafu(display("raw banner animation {path:?} must be {expected:#x} bytes but got {actual:#x} bytes:\n{backtrace}"))]
    WrongAnimationSize {
        /// Path to the raw animation.
        path: PathBuf,
        /// Expected size.
        expected: usize,
        /// Actual input size.
        actual: usize,
        /// Backtrace to the source of the error.
        backtrace: Backtrace,
    },
}

impl BannerImages {
    /// Creates a new [`BannerImages`] from a bitmap and palette.
    pub fn from_bitmap(bitmap: BannerBitmap, palette: BannerPalette) -> Self {
        Self {
            bitmap,
            palette,
            animation_bitmaps: None,
            animation_palettes: None,
            bitmap_path: "bitmap.png".into(),
            palette_path: "palette.png".into(),
            animation: None,
            animation_path: None,
        }
    }

    /// Creates a new [`BannerImages`] from a raw banner, including the animated icon if there is one.
    pub fn from_raw(banner: &raw::Banner) -> Self {
        let mut images = Self::from_bitmap(*banner.bitmap(), *banner.palette());
        if let Some(animation) = banner.animation() {
            images.animation = Some(Box::new(*animation));
            images.animation_path = Some("animation.bin".into());
        }
        images
    }

    /// Loads the bitmap and palette
    ///
    /// # Errors
    ///
    /// This function will return an error if [`Reader::open`] or [`Reader::decode`] fails, or if the images are the wrong
    /// size, or the bitmap has a color not present in the palette.
    pub fn load(&mut self, path: &Path) -> Result<(), BannerImageError> {
        let palette_image = ImageReader::open(path.join(&self.palette_path))?.decode()?;
        if palette_image.width() != 16 || palette_image.height() != 1 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 16, height: 1 },
                actual: ImageSize { width: palette_image.width(), height: palette_image.height() },
            }
            .fail();
        }

        let mut palette = BannerPalette([0u16; 16]);
        for (i, _, color) in palette_image.pixels() {
            let [r, g, b, _] = color.0;
            palette.set_color(i as usize, r, g, b);
        }

        let bitmap_path = path.join(&self.bitmap_path);
        let bitmap = match Self::load_indexed_bitmap(&bitmap_path)? {
            Some(bitmap) => bitmap,
            None => Self::load_rgba_bitmap(&bitmap_path, &palette_image)?,
        };

        self.bitmap = bitmap;
        self.palette = palette;

        if let Some(animation_path) = &self.animation_path {
            let path = path.join(animation_path);
            let data = std::fs::read(&path)?;
            let expected = size_of::<raw::BannerAnimation>();
            if data.len() != expected {
                return WrongAnimationSizeSnafu { path, expected, actual: data.len() }.fail();
            }
            self.animation = Some(Box::new(bytemuck::pod_read_unaligned(&data)));
        }
        Ok(())
    }

    /// Loads the palette indices of an indexed PNG, or returns `None` if the PNG is not indexed.
    fn load_indexed_bitmap(path: &Path) -> Result<Option<BannerBitmap>, BannerImageError> {
        let mut decoder = png::Decoder::new(BufReader::new(File::open(path)?));
        decoder.set_transformations(png::Transformations::IDENTITY);
        let mut reader = decoder.read_info()?;
        if reader.info().color_type != png::ColorType::Indexed {
            return Ok(None);
        }
        let mut data = vec![0; reader.output_buffer_size().unwrap_or_default()];
        let frame = reader.next_frame(&mut data)?;
        if frame.width != 32 || frame.height != 32 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 32, height: 32 },
                actual: ImageSize { width: frame.width, height: frame.height },
            }
            .fail();
        }

        let bits = frame.bit_depth as usize;
        let mask = (1usize << bits) - 1;
        let mut bitmap = BannerBitmap([0u8; 0x200]);
        for y in 0..32 {
            let row = &data[y * frame.line_size..];
            for x in 0..32 {
                let bit = x * bits;
                let index = (row[bit / 8] as usize >> (8 - bits - bit % 8)) & mask;
                if index >= 16 {
                    return InvalidPixelSnafu { bitmap: path.to_path_buf(), x: x as u32, y: y as u32 }.fail();
                }
                bitmap.set_pixel(x, y, index as u8);
            }
        }
        Ok(Some(bitmap))
    }

    /// Loads an RGBA PNG by looking up each pixel's color in the palette.
    fn load_rgba_bitmap(
        path: &Path,
        palette_image: &image::DynamicImage,
    ) -> Result<BannerBitmap, BannerImageError> {
        let bitmap_image = ImageReader::open(path)?.decode()?;
        if bitmap_image.width() != 32 || bitmap_image.height() != 32 {
            return WrongSizeSnafu {
                expected: ImageSize { width: 32, height: 32 },
                actual: ImageSize { width: bitmap_image.width(), height: bitmap_image.height() },
            }
            .fail();
        }

        let mut bitmap = BannerBitmap([0u8; 0x200]);
        for (x, y, color) in bitmap_image.pixels() {
            let alpha = color.0[3];
            let index = if alpha == 0 {
                0
            } else {
                let Some(index) = palette_image.pixels().find_map(|(i, _, c)| (color == c).then_some(i)) else {
                    return InvalidPixelSnafu { bitmap: path.to_path_buf(), x, y }.fail();
                };
                index
            };
            bitmap.set_pixel(x as usize, y as usize, index as u8);
        }
        Ok(bitmap)
    }

    /// Saves to a bitmap and palette file in the given path.
    ///
    /// # Errors
    ///
    /// See [`RgbImage::save`].
    pub fn save_bitmap_file(&self, path: &Path) -> Result<(), BannerImageError> {
        // Saved as an indexed PNG, so that pixels keep their palette index even if two palette colors are equal
        let mut encoder = png::Encoder::new(BufWriter::new(File::create(path.join(&self.bitmap_path))?), 32, 32);
        encoder.set_color(png::ColorType::Indexed);
        encoder.set_depth(png::BitDepth::Eight);
        let mut plte = Vec::with_capacity(16 * 3);
        let mut trns = Vec::with_capacity(16);
        for index in 0..16 {
            let [r, g, b, a] = self.palette.get_color(index);
            plte.extend([r, g, b]);
            trns.push(a);
        }
        encoder.set_palette(plte);
        encoder.set_trns(trns);
        let mut indices = [0u8; 32 * 32];
        for y in 0..32 {
            for x in 0..32 {
                indices[y * 32 + x] = self.bitmap.get_pixel(x, y) as u8;
            }
        }
        encoder.write_header()?.write_image_data(&indices)?;

        let mut palette_image = RgbaImage::new(16, 1);
        for index in 0..16 {
            let color = self.palette.get_color(index);
            palette_image.put_pixel(index as u32, 0, Rgba(color));
        }

        palette_image.save(path.join(&self.palette_path))?;

        if let (Some(animation), Some(animation_path)) = (&self.animation, &self.animation_path) {
            std::fs::write(path.join(animation_path), bytemuck::bytes_of(animation.as_ref()))?;
        }
        Ok(())
    }
}

/// Game title in different languages.
#[derive(Serialize, Deserialize, Default)]
pub struct BannerTitle {
    /// Japanese.
    pub japanese: String,
    /// English.
    pub english: String,
    /// French.
    pub french: String,
    /// German.
    pub german: String,
    /// Italian.
    pub italian: String,
    /// Spanish.
    pub spanish: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Chinese.
    pub chinese: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Korean.
    pub korean: Option<String>,
}

macro_rules! copy_title {
    ($banner:ident, $language:expr, $title:expr) => {
        if let Some(title) = $banner.title_mut($language) {
            *title = Unicode16Array::from($title.as_str());
        }
    };
}

impl BannerTitle {
    fn copy_to_banner(&self, banner: &mut raw::Banner) {
        copy_title!(banner, Language::Japanese, &self.japanese);
        copy_title!(banner, Language::English, &self.english);
        copy_title!(banner, Language::French, &self.french);
        copy_title!(banner, Language::German, &self.german);
        copy_title!(banner, Language::Italian, &self.italian);
        copy_title!(banner, Language::Spanish, &self.spanish);
        if let Some(chinese) = &self.chinese {
            copy_title!(banner, Language::Chinese, chinese);
        }
        if let Some(korean) = &self.korean {
            copy_title!(banner, Language::Korean, korean);
        }
    }
}

/// Keyframe for animated icon.
#[derive(Serialize, Deserialize)]
pub struct BannerKeyframe {
    /// Flips the bitmap vertically.
    pub flip_vertically: bool,
    /// Flips the bitmap horizontally.
    pub flip_horizontally: bool,
    /// Palette index.
    pub palette: usize,
    /// Bitmap index.
    pub bitmap: usize,
    /// Duration in frames.
    pub frame_duration: usize,
}

impl BannerKeyframe {
    /// Builds a raw keyframe.
    ///
    /// # Panics
    ///
    /// Panics if the frame duration, bitmap index or palette do not fit in the raw keyframe.
    pub fn build(&self) -> raw::BannerKeyframe {
        raw::BannerKeyframe::new()
            .with_frame_duration(self.frame_duration.try_into().unwrap())
            .with_bitmap_index(self.bitmap.try_into().unwrap())
            .with_palette_index(self.palette.try_into().unwrap())
            .with_flip_horizontally(self.flip_horizontally)
            .with_flip_vertically(self.flip_vertically)
    }
}
