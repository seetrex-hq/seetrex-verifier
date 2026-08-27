// SPDX-License-Identifier: Apache-2.0
//! `.dep-v0` -- the dependency list a binary carries about itself.
//!
//! `cargo auditable` embeds, in every binary it builds, a zlib-compressed
//! JSON document listing the exact crates that were compiled into THAT
//! artifact, in a linker section named `.dep-v0`. This module reads that
//! section out of an ELF64 image and compares it with the lockfile
//! projection of [`super::Projection`].
//!
//! ## Why the section table and not a byte search
//!
//! The literal `.dep-v0` occurs in the section-header string table of
//! every binary that carries the section, and it occurs there BEFORE the
//! payload. Searching the raw image for the name therefore finds the
//! string table and returns whatever bytes follow it -- rubbish that a
//! decompressor rejects on a good day and silently mis-parses on a bad
//! one. The section is located through the section header table, which
//! is the only structure that maps a name to an offset and a length.
//!
//! ## Why an own ELF walk and an own INFLATE
//!
//! This crate's declared identity is a verification core an auditor can
//! `cargo install` without pulling a supply chain (see the crate-purity
//! guard in `lib.rs`). An ELF reader crate costs about four transitive
//! crates and a decompression crate costs one more, for a job that is a
//! fixed table of offsets and a well specified bit format. Both are
//! implemented here, READ-ONLY, over untrusted bytes:
//!
//! - every offset and length read out of the image is bounds-checked
//!   against the image before it is used;
//! - the decompressed size is capped ([`MAX_DECOMPRESSED_BYTES`]), so a
//!   compression bomb in a hostile binary cannot exhaust memory;
//! - the Adler-32 trailer of the zlib stream is verified, so a corrupted
//!   payload is an error rather than a short dependency list.
//!
//! Nothing here executes, maps or relocates anything: the image is a
//! byte slice that is read and dropped.
//!
//! ## Does `strip` remove the section?
//!
//! Read from the two format documents, not measured here.
//!
//! - The writer creates `.dep-v0` as read-only data and sets the ELF
//!   section flags to ZERO explicitly, so the section is NOT `SHF_ALLOC`
//!   (`cargo-auditable/src/object_file.rs`, upstream). It is a non-alloc
//!   section that no program header maps.
//! - Cargo's `strip = true` selects `-C strip=symbols`, documented as
//!   "debuginfo sections and debuginfo symbols from the symbol table
//!   section are stripped at link time [...] the rest of the symbol
//!   table section is stripped as well" (rustc codegen options,
//!   `-C strip`). Neither clause names a non-debug, non-symbol-table
//!   section, and the symbol the writer adds exists to stop the LINKER
//!   discarding the section, which has already happened by the time the
//!   symbol table goes.
//!
//! The two documents therefore PREDICT that the section survives a
//! stripped release build on ELF. That prediction is not a measurement:
//! it can only be observed on a binary actually built with the tool, and
//! no binary here is. Whatever adopts the tool in a release build owns
//! the measurement, and if it comes out the other way the choice is
//! between the section and the strip -- this module does not assume
//! which wins.
//!
//! ## Direction of the comparison
//!
//! A lockfile covers a whole workspace; a `.dep-v0` section covers what
//! was compiled into one binary. The second is a subset of the first BY
//! CONSTRUCTION, so the check is one-directional: a pair in the binary
//! and not in the projection is a failure, a component of the projection
//! that the binary does not carry is information. Inverting that
//! direction turns every multi-binary workspace into a false failure.
//!
//! One pair of the binary is covered without being a component: the
//! SUBJECT. Entry 0 of a real `.dep-v0` document is the root package, and
//! the projection puts the subject in `metadata.component` rather than in
//! `components` (specification 5.5 and 7.5). Reporting it as unaccounted
//! would fail every binary the tool produces, on its own crate.

use std::collections::BTreeSet;

use serde_json::Value;

use super::Projection;

/// Name of the linker section `cargo auditable` writes.
///
/// Pinned as a constant because it is the ONE string whose exactness the
/// extractor depends on: a prefix match or an off-by-one would read a
/// neighbouring section and report its bytes as the dependency list.
pub const SECTION_NAME: &str = ".dep-v0";

/// Upper bound on the decompressed payload, in bytes.
///
/// 8 MiB is the limit the format's own parsing guidance recommends
/// against compression bombs. A real section is a few kilobytes even for
/// dependency trees with hundreds of entries, so the cap is three orders
/// of magnitude above anything legitimate.
pub const MAX_DECOMPRESSED_BYTES: usize = 8 * 1024 * 1024;

/// Errors of the `.dep-v0` extractor.
///
/// The ABSENCE of the section is deliberately NOT one of them: "this
/// binary was not built with the tool" and "this binary disagrees with
/// the SBOM" are different outcomes and collapsing them turns an
/// uninstrumented binary into a false match or a false failure.
/// [`extract_dep_v0`] reports absence as `Ok(None)`.
#[derive(Debug, thiserror::Error)]
pub enum DepV0Error {
    /// The image is not an ELF64 little-endian container. A PE or a
    /// Mach-O reaches this arm and fails loud; it never returns an empty
    /// dependency list, which would read as "built, and carries
    /// nothing".
    #[error("unsupported binary format: {detail}")]
    UnsupportedBinaryFormat {
        /// What the container looked like.
        detail: String,
    },
    /// The image claims to be ELF64 but its section table cannot be
    /// walked: truncated, out of bounds, or self-contradictory.
    #[error("malformed ELF: {detail}")]
    MalformedElf {
        /// Which structural expectation was broken.
        detail: String,
    },
    /// The section exists but is not a readable zlib stream.
    #[error("the `{SECTION_NAME}` section is not a readable zlib stream: {detail}")]
    Compression {
        /// Where the decoder stopped.
        detail: String,
    },
    /// The section decompressed but its content is not the expected
    /// document.
    #[error("the `{SECTION_NAME}` payload is not a readable dependency document: {detail}")]
    MalformedPayload {
        /// What was expected.
        detail: String,
    },
}

/// The dependency list a binary carries about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepV0 {
    /// `(name, version)` pairs, in the order the document lists them,
    /// with exact duplicates collapsed.
    pub packages: Vec<(String, String)>,
}

/// Result of comparing a projection against a binary's own list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    /// Pairs the binary carries that the projection does not contain.
    /// Non-empty means FAILURE: the artifact was built from something
    /// the published lockfile does not account for.
    pub missing: Vec<(String, String)>,
    /// How many components of the projection the binary does not carry.
    /// INFORMATIONAL: a lockfile covers a workspace, a binary does not.
    pub extra_in_projection: usize,
}

impl CoverageReport {
    /// True when every pair of the binary is accounted for by the
    /// projection. [`Self::extra_in_projection`] deliberately does not
    /// participate: it is information, not a verdict.
    pub fn is_covered(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Read the `.dep-v0` section of an ELF64 image.
///
/// Returns `Ok(None)` when the image is a well formed ELF64 that simply
/// does not carry the section -- the "not attested" outcome, which is
/// distinct from a mismatch and from a malformed image.
///
/// # Errors
///
/// [`DepV0Error::UnsupportedBinaryFormat`] for anything that is not an
/// ELF64 little-endian container, [`DepV0Error::MalformedElf`] for an
/// unwalkable section table, [`DepV0Error::Compression`] for a section
/// that is not a valid zlib stream and [`DepV0Error::MalformedPayload`]
/// for a payload that is not the expected JSON document.
pub fn extract_dep_v0(elf_bytes: &[u8]) -> Result<Option<DepV0>, DepV0Error> {
    let Some(section) = find_section(elf_bytes, SECTION_NAME)? else {
        return Ok(None);
    };
    let json = inflate::zlib_decompress(section, MAX_DECOMPRESSED_BYTES)
        .map_err(|detail| DepV0Error::Compression { detail })?;
    parse_payload(&json).map(Some)
}

/// Compare a projection against a binary's own dependency list.
///
/// The match on a component is EXACT on both halves of the pair: a name
/// present at another version is not a match, because "the same crate at
/// a different version" is precisely the difference a supply-chain check
/// exists to surface.
///
/// The one pair that is covered WITHOUT being a component is the SUBJECT.
/// Entry 0 of a real `.dep-v0` document is the root package -- the crate
/// the binary was built from -- and the projection deliberately does not
/// repeat the subject inside `components` (specification 5.5): it is
/// `metadata.component`. Treating it as unaccounted would report every
/// binary `cargo auditable` produces as missing its own crate, which is
/// the check failing on the only input it exists for. The subject is
/// matched on the same `(name, version)` pair as everything else, read
/// off the subject purl the AUDITOR supplied -- never off the binary.
pub fn check_projection_covers_binary(projection: &Projection, dep: &DepV0) -> CoverageReport {
    let components: BTreeSet<(&str, &str)> = projection
        .components()
        .iter()
        .map(|c| (c.name.as_str(), c.version.as_str()))
        .collect();
    let subject_pair = (projection.subject().name(), projection.subject().version());
    let in_binary: BTreeSet<(&str, &str)> = dep
        .packages
        .iter()
        .map(|(name, version)| (name.as_str(), version.as_str()))
        .collect();

    let missing = dep
        .packages
        .iter()
        .filter(|(name, version)| {
            let pair = (name.as_str(), version.as_str());
            pair != subject_pair && !components.contains(&pair)
        })
        .map(|(name, version)| (name.clone(), version.clone()))
        .collect();

    // Counted over the COMPONENTS alone: the subject is accounted for by
    // `metadata.component`, not by an entry of this array, so admitting it
    // above must not also inflate the informational count here.
    let extra_in_projection = components
        .iter()
        .filter(|pair| !in_binary.contains(*pair))
        .count();

    CoverageReport {
        missing,
        extra_in_projection,
    }
}

// ---------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------

/// `{"packages":[{"name":..,"version":..,..},..]}` -> the pairs.
///
/// Every other field of the document (`source`, `kind`, `root`,
/// `dependencies`) is ignored ON PURPOSE: this check answers "was this
/// crate at this version compiled in", and the fields that could narrow
/// it are producer-declared, so filtering on them would let a producer
/// shrink the set it is checked against.
fn parse_payload(json: &[u8]) -> Result<DepV0, DepV0Error> {
    let document: Value =
        serde_json::from_slice(json).map_err(|e| DepV0Error::MalformedPayload {
            detail: format!("not JSON: {e}"),
        })?;
    let entries = document
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| DepV0Error::MalformedPayload {
            detail: "no `packages` array at the root".to_string(),
        })?;

    let mut packages: Vec<(String, String)> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let field = |key: &str| -> Result<String, DepV0Error> {
            entry
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| DepV0Error::MalformedPayload {
                    detail: format!("package at index {index} carries no string `{key}`"),
                })
        };
        let pair = (field("name")?, field("version")?);
        if !packages.contains(&pair) {
            packages.push(pair);
        }
    }
    Ok(DepV0 { packages })
}

// ---------------------------------------------------------------------
// ELF64 section table
// ---------------------------------------------------------------------

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
/// `e_ident[EI_CLASS]` value for a 64-bit object.
const ELFCLASS64: u8 = 2;
/// `e_ident[EI_DATA]` value for little-endian encoding.
const ELFDATA2LSB: u8 = 1;
/// Size of the ELF64 file header, and the smallest possible image.
const EHDR_SIZE: usize = 64;
/// Size of one ELF64 section header entry.
const SHDR_SIZE: u64 = 64;
/// `sh_type` of a section that occupies no bytes in the file.
const SHT_NOBITS: u32 = 8;
/// `e_shstrndx` escape value: the real index lives in `sh_link` of
/// section header 0.
const SHN_XINDEX: u16 = 0xffff;

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

/// A `(offset, size)` pair read out of the image, resolved to a slice
/// only after both ends are proved to lie inside it.
fn slice_of(image: &[u8], offset: u64, size: u64, what: &str) -> Result<usize, DepV0Error> {
    let start = usize::try_from(offset).map_err(|_| DepV0Error::MalformedElf {
        detail: format!("{what} starts past the addressable range"),
    })?;
    let len = usize::try_from(size).map_err(|_| DepV0Error::MalformedElf {
        detail: format!("{what} is larger than the addressable range"),
    })?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| DepV0Error::MalformedElf {
            detail: format!("{what} overflows when added to its offset"),
        })?;
    if end > image.len() {
        return Err(DepV0Error::MalformedElf {
            detail: format!(
                "{what} spans bytes {start}..{end} of an image of {} bytes",
                image.len()
            ),
        });
    }
    Ok(start)
}

/// Locate a section by EXACT name through the section header table.
fn find_section<'a>(image: &'a [u8], want: &str) -> Result<Option<&'a [u8]>, DepV0Error> {
    if image.len() < 4 || &image[..4] != ELF_MAGIC {
        return Err(DepV0Error::UnsupportedBinaryFormat {
            detail: "no ELF magic in the first four bytes (PE and Mach-O are not supported)"
                .to_string(),
        });
    }
    if image.len() < EHDR_SIZE {
        return Err(DepV0Error::MalformedElf {
            detail: format!(
                "ELF64 file header needs {EHDR_SIZE} bytes, the image has {}",
                image.len()
            ),
        });
    }
    if image[4] != ELFCLASS64 {
        return Err(DepV0Error::UnsupportedBinaryFormat {
            detail: format!("ELF class {} is not ELF64", image[4]),
        });
    }
    if image[5] != ELFDATA2LSB {
        return Err(DepV0Error::UnsupportedBinaryFormat {
            detail: format!("ELF data encoding {} is not little-endian", image[5]),
        });
    }

    let e_shoff = u64_at(image, 0x28);
    if e_shoff == 0 {
        // No section header table at all. The section cannot be present,
        // which is the "not attested" outcome and not a malformed image.
        return Ok(None);
    }
    let e_shentsize = u16_at(image, 0x3a);
    if u64::from(e_shentsize) != SHDR_SIZE {
        return Err(DepV0Error::MalformedElf {
            detail: format!("section header entry size is {e_shentsize}, expected {SHDR_SIZE}"),
        });
    }

    // Section header 0 is the reserved entry that carries the escape
    // values for the two fields of the file header that are too narrow.
    let shdr0 = slice_of(image, e_shoff, SHDR_SIZE, "section header 0")?;
    let mut count = u64::from(u16_at(image, 0x3c));
    if count == 0 {
        count = u64_at(image, shdr0 + 32);
    }
    if count == 0 {
        return Ok(None);
    }
    let mut strndx = u64::from(u16_at(image, 0x3e));
    if strndx == u64::from(SHN_XINDEX) {
        strndx = u64::from(u32_at(image, shdr0 + 40));
    }

    let table_size = count
        .checked_mul(SHDR_SIZE)
        .ok_or_else(|| DepV0Error::MalformedElf {
            detail: "section header table size overflows".to_string(),
        })?;
    let table = slice_of(image, e_shoff, table_size, "section header table")?;

    if strndx >= count {
        return Err(DepV0Error::MalformedElf {
            detail: format!("section name string table index {strndx} is past the {count} entries"),
        });
    }
    let strtab_hdr = table + (strndx as usize) * (SHDR_SIZE as usize);
    let strtab_off = u64_at(image, strtab_hdr + 24);
    let strtab_len = u64_at(image, strtab_hdr + 32);
    let strtab_start = slice_of(image, strtab_off, strtab_len, "section name string table")?;
    let strtab = &image[strtab_start..strtab_start + strtab_len as usize];

    // The whole table is walked, never stopped at the first hit: an image
    // carrying the name TWICE is self-contradictory, and taking the first
    // one would let a second, later section sit in the file unread while
    // the check reported a clean verdict over the other one.
    let mut found: Option<&'a [u8]> = None;
    for index in 0..count {
        let hdr = table + (index as usize) * (SHDR_SIZE as usize);
        let sh_name = u32_at(image, hdr) as usize;
        let name = name_at(strtab, sh_name)?;
        if name != want {
            continue;
        }
        if found.is_some() {
            return Err(DepV0Error::MalformedElf {
                detail: format!(
                    "the image carries more than one section named `{want}`; which \
                     of them describes the binary is not decidable, and reading the \
                     first would leave the other unread behind a clean verdict"
                ),
            });
        }
        let sh_type = u32_at(image, hdr + 4);
        if sh_type == SHT_NOBITS {
            return Err(DepV0Error::MalformedElf {
                detail: format!("section `{want}` occupies no bytes in the file"),
            });
        }
        let sh_offset = u64_at(image, hdr + 24);
        let sh_size = u64_at(image, hdr + 32);
        let start = slice_of(image, sh_offset, sh_size, &format!("section `{want}`"))?;
        found = Some(&image[start..start + sh_size as usize]);
    }
    Ok(found)
}

/// Read the NUL-terminated name at `offset` of the string table.
fn name_at(strtab: &[u8], offset: usize) -> Result<&str, DepV0Error> {
    if offset >= strtab.len() {
        return Err(DepV0Error::MalformedElf {
            detail: format!(
                "section name offset {offset} is past the {}-byte string table",
                strtab.len()
            ),
        });
    }
    let rest = &strtab[offset..];
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| DepV0Error::MalformedElf {
            detail: format!("section name at offset {offset} is not NUL-terminated"),
        })?;
    std::str::from_utf8(&rest[..end]).map_err(|_| DepV0Error::MalformedElf {
        detail: format!("section name at offset {offset} is not UTF-8"),
    })
}

// ---------------------------------------------------------------------
// zlib / DEFLATE
// ---------------------------------------------------------------------

/// A minimal, allocation-bounded DEFLATE decoder.
///
/// RFC 1950 (zlib container) over RFC 1951 (DEFLATE). It exists so this
/// crate can read a compressed section without taking a decompression
/// dependency; it is a DECODER only, over untrusted input, and every
/// path that could grow memory is bounded by `max_output`.
mod inflate {
    /// Bit reader, least-significant bit first, as DEFLATE requires.
    struct BitReader<'a> {
        data: &'a [u8],
        pos: usize,
        buffer: u32,
        count: u32,
    }

    impl<'a> BitReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                data,
                pos: 0,
                buffer: 0,
                count: 0,
            }
        }

        /// Read `need` bits (`need` <= 24). Only ever buffers a partial
        /// byte beyond what was asked for, which is what makes
        /// [`Self::align`] a simple discard.
        fn bits(&mut self, need: u32) -> Result<u32, String> {
            while self.count < need {
                let byte = *self
                    .data
                    .get(self.pos)
                    .ok_or_else(|| "stream ends inside a block".to_string())?;
                self.pos += 1;
                self.buffer |= u32::from(byte) << self.count;
                self.count += 8;
            }
            let value = self.buffer & ((1u32 << need) - 1);
            self.buffer >>= need;
            self.count -= need;
            Ok(value)
        }

        /// Discard the current partial byte.
        fn align(&mut self) {
            self.buffer = 0;
            self.count = 0;
        }
    }

    /// A canonical Huffman code, in the counts-and-symbols form: for
    /// each code length, how many codes have it and which symbols they
    /// are, in symbol order. Decoding walks lengths one bit at a time,
    /// which needs no table build proportional to the code space.
    struct Huffman {
        counts: [u16; 16],
        symbols: Vec<u16>,
        /// Unused code space. 0 = complete code; > 0 = incomplete, which
        /// only a distance code with fewer than two symbols may be.
        slack: i32,
    }

    impl Huffman {
        fn build(lengths: &[u8]) -> Result<Self, String> {
            let mut counts = [0u16; 16];
            for &length in lengths {
                if length as usize > 15 {
                    return Err(format!("code length {length} is out of range"));
                }
                counts[length as usize] += 1;
            }
            counts[0] = 0;

            let mut slack: i32 = 1;
            for count in counts.iter().skip(1) {
                slack <<= 1;
                slack -= i32::from(*count);
                if slack < 0 {
                    return Err("over-subscribed Huffman code".to_string());
                }
            }

            let mut offsets = [0u16; 16];
            for length in 1..15 {
                offsets[length + 1] = offsets[length] + counts[length];
            }
            let mut symbols = vec![0u16; lengths.iter().filter(|&&l| l != 0).count()];
            for (symbol, &length) in lengths.iter().enumerate() {
                if length != 0 {
                    let slot = offsets[length as usize] as usize;
                    symbols[slot] = symbol as u16;
                    offsets[length as usize] += 1;
                }
            }
            Ok(Self {
                counts,
                symbols,
                slack,
            })
        }

        fn decode(&self, reader: &mut BitReader) -> Result<u16, String> {
            let mut code: i32 = 0;
            let mut first: i32 = 0;
            let mut index: i32 = 0;
            for length in 1..16 {
                code |= reader.bits(1)? as i32;
                let count = i32::from(self.counts[length]);
                if code - first < count {
                    let slot = (index + (code - first)) as usize;
                    return Ok(self.symbols[slot]);
                }
                index += count;
                first = (first + count) << 1;
                code <<= 1;
            }
            Err("invalid Huffman code".to_string())
        }
    }

    /// Base length for length symbols 257..=285.
    const LENGTH_BASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    /// Extra bits for length symbols 257..=285.
    const LENGTH_EXTRA: [u32; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    /// Base distance for distance symbols 0..=29.
    const DIST_BASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    /// Extra bits for distance symbols 0..=29.
    const DIST_EXTRA: [u32; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    /// The order in which the code-length code lengths are written.
    const CODE_LENGTH_ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    fn fixed_codes() -> Result<(Huffman, Huffman), String> {
        let mut literal = [0u8; 288];
        for (symbol, length) in literal.iter_mut().enumerate() {
            *length = match symbol {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let distance = [5u8; 30];
        Ok((Huffman::build(&literal)?, Huffman::build(&distance)?))
    }

    fn dynamic_codes(reader: &mut BitReader) -> Result<(Huffman, Huffman), String> {
        let hlit = reader.bits(5)? as usize + 257;
        let hdist = reader.bits(5)? as usize + 1;
        let hclen = reader.bits(4)? as usize + 4;
        if hlit > 286 || hdist > 30 {
            return Err(format!(
                "dynamic block declares {hlit} literal and {hdist} distance codes"
            ));
        }

        let mut code_lengths = [0u8; 19];
        for &slot in CODE_LENGTH_ORDER.iter().take(hclen) {
            code_lengths[slot] = reader.bits(3)? as u8;
        }
        let code_length_code = Huffman::build(&code_lengths)?;
        if code_length_code.slack != 0 {
            return Err("incomplete code-length code".to_string());
        }

        let mut lengths = vec![0u8; hlit + hdist];
        let mut written = 0usize;
        while written < lengths.len() {
            let symbol = code_length_code.decode(reader)?;
            let (value, repeat) = match symbol {
                0..=15 => {
                    lengths[written] = symbol as u8;
                    written += 1;
                    continue;
                }
                16 => {
                    if written == 0 {
                        return Err("repeat of a previous code length at position 0".to_string());
                    }
                    (lengths[written - 1], 3 + reader.bits(2)? as usize)
                }
                17 => (0u8, 3 + reader.bits(3)? as usize),
                18 => (0u8, 11 + reader.bits(7)? as usize),
                other => return Err(format!("invalid code-length symbol {other}")),
            };
            if written + repeat > lengths.len() {
                return Err("code-length repeat runs past the declared code count".to_string());
            }
            lengths[written..written + repeat].fill(value);
            written += repeat;
        }

        let literal = Huffman::build(&lengths[..hlit])?;
        if literal.slack != 0 {
            return Err("incomplete literal/length code".to_string());
        }
        let distance = Huffman::build(&lengths[hlit..])?;
        // An incomplete distance code is legal only when it holds fewer
        // than two symbols: a block that never emits a match.
        let used = lengths[hlit..].iter().filter(|&&l| l != 0).count();
        if distance.slack != 0 && used > 1 {
            return Err("incomplete distance code".to_string());
        }
        Ok((literal, distance))
    }

    fn adler32(data: &[u8]) -> u32 {
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in data {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    /// Decode a zlib stream, refusing to emit more than `max_output`
    /// bytes.
    pub(super) fn zlib_decompress(input: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
        if input.len() < 6 {
            return Err(format!(
                "a zlib stream needs at least 6 bytes, the section has {}",
                input.len()
            ));
        }
        let cmf = input[0];
        let flg = input[1];
        if cmf & 0x0f != 8 {
            return Err(format!("compression method {} is not DEFLATE", cmf & 0x0f));
        }
        if cmf >> 4 > 7 {
            return Err(format!("window size exponent {} is out of range", cmf >> 4));
        }
        if (u32::from(cmf) * 256 + u32::from(flg)) % 31 != 0 {
            return Err("zlib header check bits do not validate".to_string());
        }
        if flg & 0x20 != 0 {
            return Err("zlib stream uses a preset dictionary".to_string());
        }

        let mut reader = BitReader::new(&input[2..]);
        let mut out: Vec<u8> = Vec::new();
        loop {
            let final_block = reader.bits(1)? == 1;
            match reader.bits(2)? {
                0 => stored_block(&mut reader, &mut out, max_output)?,
                1 => {
                    let (literal, distance) = fixed_codes()?;
                    huffman_block(&mut reader, &mut out, &literal, &distance, max_output)?;
                }
                2 => {
                    let (literal, distance) = dynamic_codes(&mut reader)?;
                    huffman_block(&mut reader, &mut out, &literal, &distance, max_output)?;
                }
                _ => return Err("reserved DEFLATE block type".to_string()),
            }
            if final_block {
                break;
            }
        }

        reader.align();
        let trailer = &input[2 + reader.pos..];
        if trailer.len() < 4 {
            return Err("stream ends before its Adler-32 trailer".to_string());
        }
        let declared = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let computed = adler32(&out);
        if declared != computed {
            return Err(format!(
                "Adler-32 mismatch: the stream declares 0x{declared:08x}, the decoded bytes hash to 0x{computed:08x}"
            ));
        }
        Ok(out)
    }

    fn push(out: &mut Vec<u8>, byte: u8, max_output: usize) -> Result<(), String> {
        if out.len() >= max_output {
            return Err(format!(
                "decompressed payload exceeds the {max_output}-byte cap"
            ));
        }
        out.push(byte);
        Ok(())
    }

    fn stored_block(
        reader: &mut BitReader,
        out: &mut Vec<u8>,
        max_output: usize,
    ) -> Result<(), String> {
        reader.align();
        let header = reader
            .data
            .get(reader.pos..reader.pos + 4)
            .ok_or_else(|| "stored block ends before its length header".to_string())?;
        let len = usize::from(u16::from_le_bytes([header[0], header[1]]));
        let nlen = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len ^ 0xffff != nlen {
            return Err("stored block length and its complement disagree".to_string());
        }
        reader.pos += 4;
        let body = reader
            .data
            .get(reader.pos..reader.pos + len)
            .ok_or_else(|| "stored block runs past the end of the stream".to_string())?;
        if out.len() + len > max_output {
            return Err(format!(
                "decompressed payload exceeds the {max_output}-byte cap"
            ));
        }
        out.extend_from_slice(body);
        reader.pos += len;
        Ok(())
    }

    fn huffman_block(
        reader: &mut BitReader,
        out: &mut Vec<u8>,
        literal: &Huffman,
        distance: &Huffman,
        max_output: usize,
    ) -> Result<(), String> {
        loop {
            let symbol = literal.decode(reader)?;
            match symbol {
                0..=255 => push(out, symbol as u8, max_output)?,
                256 => return Ok(()),
                257..=285 => {
                    let slot = usize::from(symbol) - 257;
                    let length =
                        usize::from(LENGTH_BASE[slot]) + reader.bits(LENGTH_EXTRA[slot])? as usize;
                    let dist_symbol = usize::from(distance.decode(reader)?);
                    if dist_symbol >= DIST_BASE.len() {
                        return Err(format!("invalid distance symbol {dist_symbol}"));
                    }
                    let dist = usize::from(DIST_BASE[dist_symbol])
                        + reader.bits(DIST_EXTRA[dist_symbol])? as usize;
                    if dist > out.len() {
                        return Err(format!(
                            "back-reference of {dist} bytes into {} bytes of output",
                            out.len()
                        ));
                    }
                    // Byte by byte on purpose: DEFLATE allows the match
                    // to overlap its own tail (dist < length), which is
                    // how runs are encoded.
                    let start = out.len() - dist;
                    for offset in 0..length {
                        let byte = out[start + offset];
                        push(out, byte, max_output)?;
                    }
                }
                other => return Err(format!("invalid literal/length symbol {other}")),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn adler32_matches_the_reference_vector() {
            // RFC 1950 worked example: Adler-32 of "Wikipedia".
            assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
            assert_eq!(adler32(b""), 1);
        }

        #[test]
        fn a_reserved_block_type_is_an_error() {
            // 0x78 0x01 is a valid zlib header; the third byte sets
            // BFINAL=1 and BTYPE=3 (reserved).
            let stream = [0x78u8, 0x01, 0b0000_0111, 0, 0, 0, 0];
            let error = zlib_decompress(&stream, 1024).expect_err("reserved block type");
            assert!(error.contains("reserved"), "{error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::{Component, LockfileKind, Projection, ProjectionCounters, SubjectPurl};
    use std::path::{Path, PathBuf};

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom/depv0")
    }

    /// Read a `.hex` fixture: a leading `#` comment line, then hex
    /// digits with free whitespace.
    fn hex_fixture(name: &str) -> Vec<u8> {
        let path = fixture_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        let digits: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .flat_map(|line| line.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        hex::decode(digits).unwrap_or_else(|e| panic!("fixture {name} is not hex: {e}"))
    }

    fn text_fixture(name: &str) -> Vec<u8> {
        let path = fixture_dir().join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
    }

    // -----------------------------------------------------------------
    // Synthetic ELF64 builder
    // -----------------------------------------------------------------

    /// Build an ELF64 little-endian image, byte by byte, carrying the
    /// named sections.
    ///
    /// Deliberately hand-built rather than produced by a toolchain: no
    /// binary in this repository is compiled with the tool that writes
    /// `.dep-v0` today, so without a synthetic image the extractor would
    /// be unfalsifiable. The layout is the minimum a section walk needs:
    /// file header, then the section-name string table, then the section
    /// payloads, then the section header table.
    ///
    /// The string table is placed BEFORE the payloads on purpose: an
    /// extractor that searched the raw image for the section name would
    /// find the name in the string table first and read the wrong bytes.
    fn build_elf(sections: &[(&str, &[u8])]) -> Vec<u8> {
        // Section 0 is the reserved null entry; its name is the empty
        // string at offset 0 of the string table.
        let mut shstrtab: Vec<u8> = vec![0];
        let mut name_offsets: Vec<u32> = Vec::new();
        for (name, _) in sections {
            name_offsets.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut image = vec![0u8; EHDR_SIZE];
        let shstrtab_off = image.len() as u64;
        image.extend_from_slice(&shstrtab);

        let mut payload_spans: Vec<(u64, u64)> = Vec::new();
        for (_, body) in sections {
            payload_spans.push((image.len() as u64, body.len() as u64));
            image.extend_from_slice(body);
        }

        let shoff = image.len() as u64;
        // Entry count: null entry + one per section + the string table.
        let count = sections.len() + 2;

        let mut header = |name: u32, sh_type: u32, offset: u64, size: u64| {
            let mut entry = [0u8; SHDR_SIZE as usize];
            entry[0..4].copy_from_slice(&name.to_le_bytes());
            entry[4..8].copy_from_slice(&sh_type.to_le_bytes());
            entry[24..32].copy_from_slice(&offset.to_le_bytes());
            entry[32..40].copy_from_slice(&size.to_le_bytes());
            image.extend_from_slice(&entry);
        };

        header(0, 0, 0, 0);
        for (index, (offset, size)) in payload_spans.iter().enumerate() {
            header(name_offsets[index], 1, *offset, *size);
        }
        header(shstrtab_name, 3, shstrtab_off, shstrtab.len() as u64);

        image[0..4].copy_from_slice(ELF_MAGIC);
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = 1; // EV_CURRENT
        image[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        image[0x12..0x14].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
        image[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        image[0x34..0x36].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        image[0x3a..0x3c].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        image[0x3c..0x3e].copy_from_slice(&(count as u16).to_le_bytes());
        image[0x3e..0x40].copy_from_slice(&((count - 1) as u16).to_le_bytes());
        image
    }

    /// A zlib stream carrying `payload` in STORED blocks, built here so
    /// a test can embed arbitrary content without a fixture.
    fn zlib_stored(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x78u8, 0x01];
        let mut rest = payload;
        loop {
            let take = rest.len().min(0xffff);
            let (chunk, remainder) = rest.split_at(take);
            let last = remainder.is_empty();
            out.push(u8::from(last));
            out.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            out.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
            out.extend_from_slice(chunk);
            if last {
                break;
            }
            rest = remainder;
        }
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in payload {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        out.extend_from_slice(&(((b << 16) | a).to_be_bytes()));
        out
    }

    fn document(pairs: &[(&str, &str)]) -> Vec<u8> {
        let entries: Vec<String> = pairs
            .iter()
            .map(|(name, version)| {
                format!(
                    "{{\"name\":\"{name}\",\"version\":\"{version}\",\"source\":\"crates.io\"}}"
                )
            })
            .collect();
        format!("{{\"packages\":[{}]}}", entries.join(",")).into_bytes()
    }

    fn projection_of(pairs: &[(&str, &str)]) -> Projection {
        let components = pairs
            .iter()
            .map(|(name, version)| {
                Component::library(
                    format!("pkg:cargo/{name}@{version}"),
                    (*name).to_string(),
                    (*version).to_string(),
                )
            })
            .collect();
        Projection::new(
            LockfileKind::Cargo,
            SubjectPurl::parse("pkg:cargo/subject@1.0.0").expect("the subject purl parses"),
            components,
            Vec::new(),
            "test",
            ProjectionCounters::default(),
        )
        .expect("the projection is well formed")
    }

    // -----------------------------------------------------------------
    // Extraction
    // -----------------------------------------------------------------

    /// INTENT: the extractor locates `.dep-v0` THROUGH THE SECTION
    ///   TABLE, decompresses it and returns the embedded list. The
    ///   section name also occurs, earlier in the image, inside the
    ///   section-name string table, so an implementation that searched
    ///   the raw bytes would return the string table's neighbourhood
    ///   instead of the payload.
    /// CONTEXT: no binary produced by this repository carries the
    ///   section today, so without a synthetic image built byte by byte
    ///   the whole extractor would be unfalsifiable code.
    /// EXPIRES IF: the embedding tool changes the section name or the
    ///   payload encoding, in which case the fixtures and this test move
    ///   together in the same change.
    #[test]
    fn test_intent_dep_v0_extraction_reads_a_synthetic_elf() {
        let payload = text_fixture("auditable_payload.json");
        let compressed = hex_fixture("auditable_payload.zlib.hex");
        let image = build_elf(&[
            (".text", b"\x90\x90\x90\x90"),
            (SECTION_NAME, &compressed),
            (".comment", b"not the payload"),
        ]);

        // The literal name really does occur before the payload: this is
        // the trap the section-table walk exists to avoid.
        let name_position = image
            .windows(SECTION_NAME.len())
            .position(|w| w == SECTION_NAME.as_bytes())
            .expect("the section name is in the string table");
        let payload_position = image
            .windows(compressed.len())
            .position(|w| w == compressed.as_slice())
            .expect("the payload is in the image");
        assert!(
            name_position < payload_position,
            "the fixture must place the string table before the payload for the trap to exist"
        );

        let dep = extract_dep_v0(&image)
            .expect("a well formed image walks")
            .expect("the section is present");

        let expected = parse_payload(&payload).expect("the fixture payload parses");
        assert_eq!(dep, expected);
        assert_eq!(dep.packages.len(), 28);
        assert!(dep
            .packages
            .contains(&("serde".to_string(), "1.0.228".to_string())));
        assert!(dep
            .packages
            .contains(&("zeroize".to_string(), "1.8.1".to_string())));
    }

    /// INTENT: the section is matched by its EXACT name. A prefix or
    ///   suffix match would read a neighbouring section and report its
    ///   bytes as the dependency list of the binary.
    /// CONTEXT: section names share prefixes as a matter of course
    ///   (`.debug_info` / `.debug_info_offsets`), so an off-by-one in
    ///   the name comparison is a live failure mode, not a hypothetical.
    /// EXPIRES IF: the embedding tool starts writing more than one
    ///   section whose name begins with the pinned one.
    #[test]
    fn test_intent_dep_v0_section_name_is_matched_exactly() {
        let real = zlib_stored(&document(&[("hex", "0.4.3")]));
        let decoy = zlib_stored(&document(&[("decoy", "9.9.9")]));

        // Neighbours that differ from the pinned name by one character
        // at either end, both carrying a VALID but different document,
        // so an off-by-one reads something that parses and lies.
        let image = build_elf(&[
            (".dep-v", &decoy),
            (".dep-v01", &decoy),
            ("dep-v0", &decoy),
            (SECTION_NAME, &real),
        ]);
        let dep = extract_dep_v0(&image)
            .expect("the image walks")
            .expect("the section is present");
        assert_eq!(dep.packages, vec![("hex".to_string(), "0.4.3".to_string())]);

        // And with the exact name absent, the neighbours must NOT stand
        // in for it.
        let without = build_elf(&[(".dep-v", &decoy), (".dep-v01", &decoy), ("dep-v0", &decoy)]);
        assert_eq!(
            extract_dep_v0(&without).expect("the image walks"),
            None,
            "a section whose name merely resembles the pinned one is not the section"
        );
    }

    /// INTENT: "this binary was not built with the embedding tool" and
    ///   "this binary disagrees with the SBOM" are DIFFERENT outcomes.
    ///   Absence is `Ok(None)`, never an empty list and never an error:
    ///   an empty list would read as a binary that carries nothing, and
    ///   an error would read as a corrupt artifact.
    /// CONTEXT: that is exactly the state of every binary this
    ///   repository builds today.
    /// EXPIRES IF: the embedding tool becomes mandatory in the release
    ///   build, after which absence becomes a build regression.
    #[test]
    fn test_intent_dep_v0_absent_is_a_distinct_outcome() {
        let image = build_elf(&[(".text", b"\x90\x90"), (".rodata", b"payload")]);
        assert_eq!(
            extract_dep_v0(&image).expect("a well formed image without the section walks"),
            None
        );

        // Same claim for an ELF with no section header table at all.
        let mut headerless = image.clone();
        headerless[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        headerless[0x3c..0x3e].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            extract_dep_v0(&headerless).expect("an ELF with no section table walks"),
            None
        );
    }

    /// INTENT: a container that is not ELF64 little-endian fails LOUD.
    ///   Returning an empty list for a PE would report "built, carries
    ///   no dependencies", which is a false pass on an artifact the
    ///   checker cannot read at all.
    /// CONTEXT: the release targets are ELF, but the auditor runs the
    ///   tool on whatever file is handed to them.
    /// EXPIRES IF: PE or Mach-O support is added, at which point each
    ///   gets its own extractor and its own tests.
    #[test]
    fn test_intent_dep_v0_non_elf_is_fail_loud() {
        // A minimal PE: "MZ" and the `PE\0\0` signature.
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(matches!(
            extract_dep_v0(&pe),
            Err(DepV0Error::UnsupportedBinaryFormat { .. })
        ));

        // A 32-bit ELF and a big-endian ELF are ELF, and still not the
        // container this extractor reads.
        let mut elf32 = build_elf(&[(".text", b"\x90")]);
        elf32[4] = 1;
        assert!(matches!(
            extract_dep_v0(&elf32),
            Err(DepV0Error::UnsupportedBinaryFormat { .. })
        ));
        let mut big_endian = build_elf(&[(".text", b"\x90")]);
        big_endian[5] = 2;
        assert!(matches!(
            extract_dep_v0(&big_endian),
            Err(DepV0Error::UnsupportedBinaryFormat { .. })
        ));

        // An empty file is not an ELF either.
        assert!(matches!(
            extract_dep_v0(&[]),
            Err(DepV0Error::UnsupportedBinaryFormat { .. })
        ));
    }

    /// INTENT: a section table that does not fit the image is an ERROR,
    ///   never a silent "no section here". Every offset and length taken
    ///   from the image is bounds-checked before it is used, so a
    ///   truncated or hostile file cannot make the walk read outside the
    ///   slice or report a short list.
    /// CONTEXT: the input is an untrusted artifact handed over by the
    ///   party being audited.
    /// EXPIRES IF: the extractor stops reading whole images into memory
    ///   and gains a streaming reader, which needs its own bounds tests.
    #[test]
    fn test_intent_dep_v0_truncated_section_table_is_an_error() {
        let compressed = zlib_stored(&document(&[("hex", "0.4.3")]));
        let image = build_elf(&[(SECTION_NAME, &compressed)]);

        // Cut the image inside the section header table.
        let shoff = u64_at(&image, 0x28) as usize;
        let truncated = &image[..shoff + 8];
        assert!(
            matches!(
                extract_dep_v0(truncated),
                Err(DepV0Error::MalformedElf { .. })
            ),
            "a section header table that runs past the end of the file must fail loud"
        );

        // A section table that starts past the end of the file.
        let mut runaway = image.clone();
        runaway[0x28..0x30].copy_from_slice(&(image.len() as u64 + 4096).to_le_bytes());
        assert!(matches!(
            extract_dep_v0(&runaway),
            Err(DepV0Error::MalformedElf { .. })
        ));

        // A string table index past the end of the table.
        let mut bad_strndx = image.clone();
        bad_strndx[0x3e..0x40].copy_from_slice(&999u16.to_le_bytes());
        assert!(matches!(
            extract_dep_v0(&bad_strndx),
            Err(DepV0Error::MalformedElf { .. })
        ));

        // A section whose payload runs past the end of the file.
        let mut runaway_section = image.clone();
        let shdr = shoff + (SHDR_SIZE as usize); // the first real section
        runaway_section[shdr + 32..shdr + 40]
            .copy_from_slice(&(image.len() as u64 * 4).to_le_bytes());
        assert!(matches!(
            extract_dep_v0(&runaway_section),
            Err(DepV0Error::MalformedElf { .. })
        ));
    }

    // -----------------------------------------------------------------
    // Decompression
    // -----------------------------------------------------------------

    /// INTENT: the own INFLATE decodes the three DEFLATE block types the
    ///   format can produce -- stored, fixed Huffman and dynamic Huffman
    ///   -- against streams a REFERENCE compressor produced, and
    ///   verifies the Adler-32 trailer. A decoder that only handled
    ///   stored blocks would pass a hand-built test and fail on every
    ///   real binary, since a real section is compressed at the default
    ///   level and comes out dynamic.
    /// CONTEXT: an own decoder exists so this crate stays installable
    ///   without a decompression dependency; the price of that choice is
    ///   paid here, with fixtures generated by a reference
    ///   implementation.
    /// EXPIRES IF: a decompression crate is adopted as a normal
    ///   dependency, in which case the own decoder and this test
    ///   disappear together.
    #[test]
    fn test_intent_dep_v0_inflate_reads_every_deflate_block_type() {
        let big = text_fixture("auditable_payload.json");
        let small = text_fixture("small_payload.json");

        for (fixture, expected) in [
            ("auditable_payload.zlib.hex", &big),
            ("small_payload.zlib.hex", &small),
            ("small_payload_stored.zlib.hex", &small),
        ] {
            let stream = hex_fixture(fixture);
            let decoded = inflate::zlib_decompress(&stream, MAX_DECOMPRESSED_BYTES)
                .unwrap_or_else(|e| panic!("{fixture} decodes: {e}"));
            assert_eq!(&decoded, expected, "{fixture} decodes to its plaintext");
        }

        // The fixtures really do cover the three block types: BTYPE is
        // bits 1..3 of the first byte after the two-byte zlib header.
        for (fixture, btype) in [
            ("auditable_payload.zlib.hex", 2u8),
            ("small_payload.zlib.hex", 1u8),
            ("small_payload_stored.zlib.hex", 0u8),
        ] {
            let stream = hex_fixture(fixture);
            assert_eq!(
                (stream[2] >> 1) & 0b11,
                btype,
                "{fixture} no longer carries the block type this test covers"
            );
        }

        // A corrupted trailer is an error, not a short read.
        let bad = hex_fixture("small_payload_bad_adler.zlib.hex");
        let error = inflate::zlib_decompress(&bad, MAX_DECOMPRESSED_BYTES)
            .expect_err("a corrupted Adler-32 trailer is rejected");
        assert!(error.contains("Adler-32"), "{error}");
    }

    /// INTENT: the decoder refuses to emit more than its cap, so a
    ///   compression bomb inside a hostile binary cannot exhaust memory
    ///   before anything else in the pipeline gets a say.
    /// CONTEXT: the binary under check is supplied by the party being
    ///   audited; the format's own parsing guidance recommends this cap.
    /// EXPIRES IF: the extractor stops holding the payload in memory.
    #[test]
    fn test_intent_dep_v0_decompression_is_bounded() {
        let payload = vec![b'A'; 4096];
        let stream = zlib_stored(&payload);
        assert!(inflate::zlib_decompress(&stream, 4096).is_ok());
        let error = inflate::zlib_decompress(&stream, 64)
            .expect_err("the cap is enforced on stored blocks");
        assert!(error.contains("cap"), "{error}");

        // And on Huffman blocks, where the output grows byte by byte.
        let compressed = hex_fixture("auditable_payload.zlib.hex");
        let error = inflate::zlib_decompress(&compressed, 64)
            .expect_err("the cap is enforced on Huffman blocks");
        assert!(error.contains("cap"), "{error}");
    }

    /// INTENT: a section that is not the expected document is an error
    ///   naming what was wrong, never a partial list. A payload missing
    ///   a `version` must not yield a package with an empty version,
    ///   which would then compare equal to nothing and be reported as a
    ///   mismatch of the SBOM rather than of the binary.
    /// CONTEXT: the payload is producer-supplied bytes.
    /// EXPIRES IF: the document grows a shape where a package
    ///   legitimately carries no version.
    #[test]
    fn test_intent_dep_v0_malformed_payload_is_an_error() {
        let cases: [&[u8]; 4] = [
            b"not json at all",
            b"{}",
            b"{\"packages\":{}}",
            b"{\"packages\":[{\"name\":\"hex\"}]}",
        ];
        for case in cases {
            let image = build_elf(&[(SECTION_NAME, &zlib_stored(case))]);
            assert!(
                matches!(
                    extract_dep_v0(&image),
                    Err(DepV0Error::MalformedPayload { .. })
                ),
                "payload {:?} must fail loud",
                String::from_utf8_lossy(case)
            );
        }

        // A section that is not a zlib stream at all.
        let image = build_elf(&[(SECTION_NAME, b"\x00\x00\x00\x00\x00\x00")]);
        assert!(matches!(
            extract_dep_v0(&image),
            Err(DepV0Error::Compression { .. })
        ));
    }

    // -----------------------------------------------------------------
    // Coverage
    // -----------------------------------------------------------------

    /// INTENT: the comparison is ONE-DIRECTIONAL. Every pair the binary
    ///   carries must be in the projection; components of the projection
    ///   the binary does not carry are counted, not failed. A lockfile
    ///   covers a workspace and a binary covers itself, so inverting the
    ///   direction fails every multi-crate workspace by construction.
    /// CONTEXT: this workspace builds several binaries from one
    ///   lockfile, so the informational side is the normal case, not an
    ///   edge case.
    /// EXPIRES IF: the projection is ever narrowed to exactly one
    ///   binary's dependency closure.
    #[test]
    fn test_intent_dep_v0_coverage_is_subset_not_equality() {
        let dep = DepV0 {
            packages: vec![
                ("serde".to_string(), "1.0.228".to_string()),
                ("hex".to_string(), "0.4.3".to_string()),
            ],
        };
        let projection = projection_of(&[
            ("serde", "1.0.228"),
            ("hex", "0.4.3"),
            ("sha2", "0.10.9"),
            ("uuid", "1.17.0"),
        ]);

        let report = check_projection_covers_binary(&projection, &dep);
        assert!(report.missing.is_empty(), "{:?}", report.missing);
        assert!(report.is_covered());
        assert_eq!(
            report.extra_in_projection, 2,
            "components of the projection the binary does not carry are INFORMATION"
        );
    }

    /// INTENT: the pair naming the SUBJECT is covered, even though the
    ///   subject is not a component. Entry 0 of a real `.dep-v0` document
    ///   is the root package -- the crate the binary was built from -- and
    ///   the projection puts the subject in `metadata.component`, never in
    ///   `components` (specification 5.5). Without this the check reported
    ///   every binary `cargo auditable` produces as missing its own crate:
    ///   a failure on the only input the check exists for.
    /// CONTEXT: the synthetic fixtures of this file happened to use a
    ///   subject (`pkg:cargo/subject@1.0.0`) that no `.dep-v0` payload
    ///   named, so the whole class was invisible here while being
    ///   universal in the field.
    /// EXPIRES IF: the subject is ever also emitted as a component, which
    ///   specification 5.5 forbids because it would put one purl on two
    ///   objects.
    #[test]
    fn test_intent_dep_v0_subject_pair_is_covered_by_metadata_component() {
        let subject = SubjectPurl::parse("pkg:cargo/root-app@1.4.2").expect("the subject parses");
        let projection = Projection::new(
            LockfileKind::Cargo,
            subject.clone(),
            vec![Component::library(
                "pkg:cargo/serde@1.0.228".to_string(),
                "serde".to_string(),
                "1.0.228".to_string(),
            )],
            Vec::new(),
            "test",
            ProjectionCounters::default(),
        )
        .expect("the projection is well formed");

        // Non-vacuity: the subject really is absent from the components,
        // which is exactly the shape the specification requires.
        assert!(
            projection
                .components()
                .iter()
                .all(|c| c.purl != subject.as_str()),
            "the subject must not be a component, or this test measures nothing"
        );

        // The binary lists its ROOT package first, the way the tool writes
        // it, then its dependencies.
        let with_root = DepV0 {
            packages: vec![
                ("root-app".to_string(), "1.4.2".to_string()),
                ("serde".to_string(), "1.0.228".to_string()),
            ],
        };
        let report = check_projection_covers_binary(&projection, &with_root);
        assert!(
            report.is_covered(),
            "the root package of the binary IS the subject and must be \
             accounted for by `metadata.component`: {:?}",
            report.missing
        );
        assert_eq!(
            report.extra_in_projection, 0,
            "admitting the subject must not also inflate the informational \
             count, which is over the COMPONENTS"
        );

        // A DIFFERENT root is still missing: the pair is matched, not
        // waved through, so a binary built from another crate entirely
        // does not pass by carrying a root entry at all.
        let other_root = DepV0 {
            packages: vec![
                ("other-app".to_string(), "1.4.2".to_string()),
                ("serde".to_string(), "1.0.228".to_string()),
            ],
        };
        let report = check_projection_covers_binary(&projection, &other_root);
        assert_eq!(
            report.missing,
            vec![("other-app".to_string(), "1.4.2".to_string())],
            "a root that is not the subject is unaccounted for"
        );

        // And so is the subject NAME at another version: both halves of
        // the pair participate here as everywhere else.
        let other_version = DepV0 {
            packages: vec![("root-app".to_string(), "9.9.9".to_string())],
        };
        assert_eq!(
            check_projection_covers_binary(&projection, &other_version).missing,
            vec![("root-app".to_string(), "9.9.9".to_string())],
            "the subject at another version is not the subject"
        );
    }

    /// INTENT: an image carrying TWO sections named `.dep-v0` is
    ///   `MalformedElf`, not a silent read of the first one. Which of the
    ///   two describes the binary is not decidable, and answering from the
    ///   first leaves the second sitting in the file behind a clean
    ///   verdict -- the shape of a hostile artifact that shows the checker
    ///   one list and the loader another.
    /// CONTEXT: the walk returned at the first name match, so the second
    ///   section was never even looked at.
    /// EXPIRES IF: the embedding tool starts writing more than one such
    ///   section with a defined precedence between them.
    #[test]
    fn test_intent_dep_v0_two_sections_of_that_name_are_fail_loud() {
        let honest = zlib_stored(&document(&[("hex", "0.4.3")]));
        let decoy = zlib_stored(&document(&[("backdoor", "9.9.9")]));

        // Both orders, so the answer does not depend on which one comes
        // first in the table.
        for pair in [
            [(SECTION_NAME, honest.as_slice()), (SECTION_NAME, &decoy)],
            [(SECTION_NAME, decoy.as_slice()), (SECTION_NAME, &honest)],
        ] {
            let image = build_elf(&pair);
            let error =
                extract_dep_v0(&image).expect_err("two sections of that name must fail loud");
            assert!(
                matches!(error, DepV0Error::MalformedElf { .. }),
                "expected MalformedElf, got {error:?}"
            );
        }

        // Control: ONE section of that name, beside a differently named
        // one carrying the same bytes, still reads.
        let image = build_elf(&[(SECTION_NAME, &honest), (".comment", &decoy)]);
        let dep = extract_dep_v0(&image)
            .expect("one section of that name walks")
            .expect("the section is present");
        assert_eq!(dep.packages, vec![("hex".to_string(), "0.4.3".to_string())]);
    }

    /// INTENT: a pair the binary carries and the projection does not is
    ///   reported as MISSING -- the failure the check exists for.
    /// CONTEXT: a crate compiled into the artifact but absent from the
    ///   published lockfile is the exact shape of an unaccounted
    ///   supply-chain input.
    /// EXPIRES IF: the direction of the check changes, which would
    ///   contradict the intent above.
    #[test]
    fn test_intent_dep_v0_pair_absent_from_the_projection_is_missing() {
        let dep = DepV0 {
            packages: vec![
                ("serde".to_string(), "1.0.228".to_string()),
                ("unaccounted".to_string(), "0.1.0".to_string()),
            ],
        };
        let projection = projection_of(&[("serde", "1.0.228")]);

        let report = check_projection_covers_binary(&projection, &dep);
        assert_eq!(
            report.missing,
            vec![("unaccounted".to_string(), "0.1.0".to_string())]
        );
        assert!(!report.is_covered());
    }

    /// INTENT: the match is on the PAIR, not on the name. The same crate
    ///   at another version is a different component, and reporting it
    ///   as covered would make the check blind to precisely the
    ///   substitution a vulnerability report is about.
    /// CONTEXT: one lockfile routinely resolves several versions of the
    ///   same crate, which is why the projection keys components by
    ///   purl rather than by name.
    /// EXPIRES IF: nothing short of the comparison changing meaning.
    #[test]
    fn test_intent_dep_v0_version_participates_in_the_match() {
        let dep = DepV0 {
            packages: vec![("serde".to_string(), "1.0.228".to_string())],
        };
        // Same name, other version -- and a second entry under the same
        // name, so a name-only match would find SOMETHING either way.
        let projection = projection_of(&[("serde", "1.0.100"), ("serde", "0.9.0")]);

        let report = check_projection_covers_binary(&projection, &dep);
        assert_eq!(
            report.missing,
            vec![("serde".to_string(), "1.0.228".to_string())],
            "a name present at another version is not a match"
        );
        assert_eq!(report.extra_in_projection, 2);
    }

    /// INTENT: the whole path holds end to end -- a synthetic binary
    ///   carrying the section, compared against a projection built from
    ///   the same pairs, is covered; drop one component from the
    ///   projection and it stops being covered.
    /// CONTEXT: the unit tests above pin each half; this pins that they
    ///   compose.
    /// EXPIRES IF: the extractor and the comparison stop sharing the
    ///   `(name, version)` pair as their interface.
    #[test]
    fn test_scenario_binary_against_its_own_projection() {
        let payload = text_fixture("auditable_payload.json");
        let compressed = hex_fixture("auditable_payload.zlib.hex");
        let image = build_elf(&[(".text", b"\x90"), (SECTION_NAME, &compressed)]);
        let dep = extract_dep_v0(&image)
            .expect("the image walks")
            .expect("the section is present");

        let expected = parse_payload(&payload).expect("the fixture parses");
        let pairs: Vec<(&str, &str)> = expected
            .packages
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();

        let complete = check_projection_covers_binary(&projection_of(&pairs), &dep);
        assert!(complete.is_covered(), "{:?}", complete.missing);
        assert_eq!(complete.extra_in_projection, 0);

        let short = check_projection_covers_binary(&projection_of(&pairs[1..]), &dep);
        assert_eq!(short.missing.len(), 1);
        assert_eq!(short.missing[0].0, pairs[0].0);
    }
}
