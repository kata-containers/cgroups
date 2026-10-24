// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Pure parser for mountinfo records in the format described by proc(5).
//!
//! The functions here transform supplied text or bytes into [`CgroupMountTable`]
//! values and never perform I/O; reading `/proc/self/mountinfo` belongs to
//! the topology layer.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use crate::core::error::ParseMountError;

use super::byte_lines;

/// A single mount record with its escaped fields decoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MountRecord {
    /// Root of the mount within the mounted filesystem.
    pub mount_root: PathBuf,
    /// Pathname of the mount point relative to the process's root.
    pub mount_point: PathBuf,
    /// Filesystem type: main type with an optional subtype.
    pub fs_type: (String, Option<String>),
    /// Superblock options, split on literal commas and escape-decoded as bytes.
    pub super_opts: Vec<Vec<u8>>,
}

/// The mounts parsed from a mountinfo stream.
///
/// The table retains every parsed mount, not only cgroup mounts; use
/// [`CgroupMountTable::cgroup_mounts`] and [`CgroupMountTable::unified_mounts`] to
/// select the cgroup-relevant subsets. Hybrid layouts therefore keep both
/// their cgroup and cgroup2 mounts instead of picking one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupMountTable {
    records: Vec<MountRecord>,
}

impl CgroupMountTable {
    /// All parsed mount records, in input order.
    pub fn records(&self) -> &[MountRecord] {
        &self.records
    }

    /// Rebase stored mount points for unit-test fixtures, retaining other fields.
    #[cfg(test)]
    pub(crate) fn map_mount_points(mut self, rebase: &impl Fn(&Path) -> PathBuf) -> Self {
        for record in &mut self.records {
            record.mount_point = rebase(&record.mount_point);
        }
        self
    }

    /// cgroup v1 mounts, in input order.
    pub fn cgroup_mounts(&self) -> Vec<&MountRecord> {
        self.records
            .iter()
            .filter(|record| record.fs_type.0 == "cgroup")
            .collect()
    }

    /// Find the first v1 mount whose super options contain `controller`, byte-exact.
    ///
    /// Preserve the existing handle policy of taking the first match in
    /// mountinfo order: duplicate binds can expose different `mount_root`s,
    /// so handles and manager maps must use the same record for the mount
    /// point and root.
    pub(crate) fn find_v1_record(&self, controller: &str) -> Option<&MountRecord> {
        self.records.iter().find(|mount| {
            mount.fs_type.0 == "cgroup"
                && mount
                    .super_opts
                    .iter()
                    .any(|option| option.as_slice() == controller.as_bytes())
        })
    }

    /// cgroup v2 (unified) mounts, in input order.
    pub fn unified_mounts(&self) -> Vec<&MountRecord> {
        self.records
            .iter()
            .filter(|record| record.fs_type.0 == "cgroup2")
            .collect()
    }
}

/// Parse a mountinfo stream into a [`CgroupMountTable`].
///
/// # Contract
///
/// - Every line is validated; a malformed line returns a
///   [`ParseMountError`] variant carrying the 1-based line number and
///   relevant input. Empty input parses to an empty table.
/// - Escaped fields are decoded per proc(5) and `fs/proc_namespace.c`:
///   `\040` (space), `\011` (tab), `\012` (newline), and `\134`
///   (backslash), plus `\043` (`#`) in the mangled filesystem-type and
///   source fields. Super options also decode `\054` (comma) and `\075`
///   (`=`). Unknown escapes are errors in the mount fields; super options
///   preserve them because filesystem-specific `show_options` output need
///   not use `seq_show_option`.
/// - All mounts are retained, not only cgroup mounts.
pub fn parse_mountinfo(input: &str) -> Result<CgroupMountTable, ParseMountError> {
    parse_mountinfo_bytes(input.as_bytes())
}

/// Parse a mountinfo stream from its procfs byte representation.
///
/// This is the host-facing entry point: mount roots, mount points, and mount
/// sources and superblock option values are kernel data and are not required
/// to be valid UTF-8.
pub fn parse_mountinfo_bytes(input: &[u8]) -> Result<CgroupMountTable, ParseMountError> {
    let mut records = Vec::new();
    for (index, line) in byte_lines(input).enumerate() {
        records.push(parse_mountinfo_line_bytes(line, index + 1)?);
    }
    Ok(CgroupMountTable { records })
}

#[derive(Clone, Copy)]
enum EscapeSet {
    Path,
    Mangled,
    SuperOption,
}

/// Parse and validate a single mountinfo line.
///
/// `line_no` is the 1-based position of `line` in the stream and is
/// reported in [`ParseMountError`] on failure.
///
/// The line is split on the first literal ` - `: escaped fields can never
/// contain it unescaped. The mount ID, parent ID, and `major:minor`
/// device field are validated as integers. `mount_root` is escape-decoded
/// but otherwise opaque: filesystems implement `show_path` themselves
/// and may emit non-path tokens (nsfs emits `net:[4026534327]`), so no
/// absolute-path assumption is made. `mount_point` is escape-decoded and
/// must be an absolute path, because the VFS (not the filesystem)
/// generates it. Mount root, mount options, filesystem type, and super
/// options must be non-empty; the mount source must be present but may be
/// empty. The mount root is required to be non-empty only, never absolute. The
/// mount options and the optional fields (`shared:` and friends) are not
/// retained; per proc(5), unrecognized optional fields are ignored. The
/// filesystem type and source are decoded with the mangled escape set,
/// and the type is split on its first `.` into main type and optional
/// subtype. Super options occupy the remainder of the line. They are split
/// on literal commas and then escape-decoded as bytes into
/// [`MountRecord::super_opts`], so an escaped comma stays in its option.
///
/// Crate-visible for focused compatibility tests; the stable public surfaces
/// are [`parse_mountinfo`] and [`parse_mountinfo_bytes`].
#[cfg(test)]
pub(crate) fn parse_mountinfo_line(
    line: &str,
    line_no: usize,
) -> Result<MountRecord, ParseMountError> {
    parse_mountinfo_line_bytes(line.as_bytes(), line_no)
}

/// Byte-oriented implementation of [`parse_mountinfo_line`].
pub(crate) fn parse_mountinfo_line_bytes(
    line: &[u8],
    line_no: usize,
) -> Result<MountRecord, ParseMountError> {
    let separator = line.windows(3).position(|window| window == b" - ");
    let separator = match separator {
        Some(separator) => separator,
        None => return Err(ParseMountError::MissingSeparator { line: line_no }),
    };
    let shared = &line[..separator];
    let fs_part = &line[separator + 3..];

    let shared_fields: Vec<&[u8]> = shared.split(|byte| *byte == b' ').collect();
    if shared_fields.len() < 6 {
        return Err(ParseMountError::MissingMountFields {
            line: line_no,
            found: shared_fields.len(),
        });
    }
    if parse_u32(shared_fields[0]).is_none() {
        return Err(ParseMountError::InvalidMountId {
            line: line_no,
            input: OsStr::from_bytes(shared_fields[0]).to_os_string(),
        });
    }
    if parse_u32(shared_fields[1]).is_none() {
        return Err(ParseMountError::InvalidParentId {
            line: line_no,
            input: OsStr::from_bytes(shared_fields[1]).to_os_string(),
        });
    }
    let mut device_parts = shared_fields[2].splitn(2, |byte| *byte == b':');
    let major = device_parts.next().unwrap_or_default();
    let minor = match device_parts.next() {
        Some(minor) => minor,
        None => {
            return Err(ParseMountError::InvalidDevice {
                line: line_no,
                input: OsStr::from_bytes(shared_fields[2]).to_os_string(),
            })
        }
    };
    if parse_u32(major).is_none() || parse_u32(minor).is_none() {
        return Err(ParseMountError::InvalidDevice {
            line: line_no,
            input: OsStr::from_bytes(shared_fields[2]).to_os_string(),
        });
    }

    if shared_fields[3].is_empty() {
        return Err(ParseMountError::EmptyMountRoot { line: line_no });
    }
    if shared_fields[5].is_empty() {
        return Err(ParseMountError::EmptyMountOptions { line: line_no });
    }

    let mount_root =
        decode_escaped_field(shared_fields[3], EscapeSet::Path, line_no, "mount root")?;
    let mount_point =
        decode_escaped_field(shared_fields[4], EscapeSet::Path, line_no, "mount point")?;
    if !mount_point.starts_with(b"/") {
        return Err(ParseMountError::NonAbsoluteMountPoint {
            line: line_no,
            input: PathBuf::from(OsStr::from_bytes(&mount_point)),
        });
    }

    let fs_fields: Vec<&[u8]> = fs_part.splitn(3, |byte| *byte == b' ').collect();
    if fs_fields.len() != 3 {
        return Err(ParseMountError::MissingFilesystemFields {
            line: line_no,
            found: fs_fields.len(),
        });
    }
    if fs_fields[0].is_empty() {
        return Err(ParseMountError::EmptyFilesystemType { line: line_no });
    }
    if fs_fields[2].is_empty() {
        return Err(ParseMountError::EmptySuperOptions { line: line_no });
    }
    let fs_type_raw =
        decode_escaped_field(fs_fields[0], EscapeSet::Mangled, line_no, "filesystem type")?;
    let fs_type_raw = String::from_utf8(fs_type_raw).map_err(|_| {
        ParseMountError::InvalidFilesystemTypeEncoding {
            line: line_no,
            input: OsStr::from_bytes(fs_fields[0]).to_os_string(),
        }
    })?;
    let (fs_type, fs_subtype) = match fs_type_raw.split_once('.') {
        Some(("", _)) => {
            return Err(ParseMountError::EmptyFilesystemTypeBeforeSubtype { line: line_no })
        }
        Some((_, "")) => return Err(ParseMountError::EmptyFilesystemSubtype { line: line_no }),
        Some((fs_type, subtype)) => (fs_type.to_string(), Some(subtype.to_string())),
        None => (fs_type_raw, None),
    };
    // The mount source must be well-formed (its escapes are validated)
    // but is not retained in a `MountRecord`.
    decode_escaped_field(fs_fields[1], EscapeSet::Mangled, line_no, "mount source")?;

    let super_opts = fs_fields[2]
        .split(|byte| *byte == b',')
        .map(|opt| decode_escaped_field(opt, EscapeSet::SuperOption, line_no, "super option"))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MountRecord {
        mount_root: PathBuf::from(OsStr::from_bytes(&mount_root)),
        mount_point: PathBuf::from(OsStr::from_bytes(&mount_point)),
        fs_type: (fs_type, fs_subtype),
        super_opts,
    })
}

/// Decode one escaped mountinfo field.
///
/// Mount fields require recognized escapes. Super options may come from
/// filesystem-specific formatters, so unknown backslashes remain literal.
fn decode_escaped_field(
    raw: &[u8],
    escapes: EscapeSet,
    line_no: usize,
    field: &'static str,
) -> Result<Vec<u8>, ParseMountError> {
    if !raw.contains(&b'\\') {
        return Ok(raw.to_vec());
    }

    let mut decoded = Vec::with_capacity(raw.len());
    let mut plain = 0;
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'\\' {
            i += 1;
            continue;
        }
        let replacement = match raw.get(i..i + 4) {
            Some(b"\\040") => b' ',
            Some(b"\\011") => b'\t',
            Some(b"\\012") => b'\n',
            Some(b"\\134") => b'\\',
            Some(b"\\043") if matches!(escapes, EscapeSet::Mangled) => b'#',
            Some(b"\\054") if matches!(escapes, EscapeSet::SuperOption) => b',',
            Some(b"\\075") if matches!(escapes, EscapeSet::SuperOption) => b'=',
            _ if matches!(escapes, EscapeSet::SuperOption) => {
                i += 1;
                continue;
            }
            _ => {
                let end = std::cmp::min(i + 4, raw.len());
                return Err(ParseMountError::InvalidEscape {
                    line: line_no,
                    field,
                    input: OsStr::from_bytes(&raw[i..end]).to_os_string(),
                });
            }
        };
        decoded.extend_from_slice(&raw[plain..i]);
        decoded.push(replacement);
        i += 4;
        plain = i;
    }
    decoded.extend_from_slice(&raw[plain..]);
    Ok(decoded)
}

fn parse_u32(raw: &[u8]) -> Option<u32> {
    std::str::from_utf8(raw).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned expectation for a parsed mountinfo line: mount_root,
    /// mount_point, fs_type main, fs_type subtype, super_opts.
    type Expect = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static [&'static str],
    );

    struct Case {
        name: &'static str,
        line: &'static str,
        expect: Option<Expect>,
    }

    const CASES: &[Case] = &[
        Case {
            name: "v1: systemd named hierarchy",
            line: "35 33 0:30 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd",
            expect: Some(("/", "/sys/fs/cgroup/systemd", "cgroup", None, &["rw", "xattr", "name=systemd"])),
        },
        Case {
            name: "v1: co-mounted controllers",
            line: "48 33 0:43 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:25 - cgroup cgroup rw,cpu,cpuacct",
            expect: Some(("/", "/sys/fs/cgroup/cpu,cpuacct", "cgroup", None, &["rw", "cpu", "cpuacct"])),
        },
        Case {
            name: "v2: unified mount",
            line: "47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw",
            expect: Some(("/", "/sys/fs/cgroup", "cgroup2", None, &["rw"])),
        },
        Case {
            name: "namespaced: mount_root is not /",
            line: "30 24 0:28 /cgroot/abc /mnt/cgroup rw,relatime master:2 - cgroup cgroup rw,cpuset",
            expect: Some(("/cgroot/abc", "/mnt/cgroup", "cgroup", None, &["rw", "cpuset"])),
        },
        Case {
            name: "nsfs: show_path emits a non-path root token",
            line: "31 23 0:23 net:[4026534327] /run/netns/default rw - nsfs nsfs rw",
            expect: Some(("net:[4026534327]", "/run/netns/default", "nsfs", None, &["rw"])),
        },
        Case {
            name: "escaped: space in mount_point",
            line: "36 35 98:0 / /my\\040mount rw,relatime - ext3 /dev/root rw,errors=continue",
            expect: Some(("/", "/my mount", "ext3", None, &["rw", "errors=continue"])),
        },
        Case {
            name: "escaped: tab in mount_point",
            line: "36 35 98:0 / /a\\011b rw - ext3 /dev/root rw",
            expect: Some(("/", "/a\tb", "ext3", None, &["rw"])),
        },
        Case {
            name: "escaped: newline in mount_point",
            line: "36 35 98:0 / /n\\012l rw - ext3 /dev/root rw",
            expect: Some(("/", "/n\nl", "ext3", None, &["rw"])),
        },
        Case {
            name: "escaped: backslash in mount_point",
            line: "36 35 98:0 / /x\\134y rw - ext3 /dev/root rw",
            expect: Some(("/", "/x\\y", "ext3", None, &["rw"])),
        },
        Case {
            name: "escaped: space in mount_root",
            line: "36 35 98:0 /root\\040dir /mnt rw - ext3 /dev/root rw",
            expect: Some(("/root dir", "/mnt", "ext3", None, &["rw"])),
        },
        Case {
            name: "escaped: source is validated but not retained",
            line: "36 35 98:0 / /mnt rw - ext3 /my\\040disk rw",
            expect: Some(("/", "/mnt", "ext3", None, &["rw"])),
        },
        Case {
            name: "empty mount source",
            line: "36 35 98:0 / /mnt rw - tmpfs  rw,size=4096",
            expect: Some(("/", "/mnt", "tmpfs", None, &["rw", "size=4096"])),
        },
        Case {
            name: "escaped: super option values retain commas and other escaped bytes",
            line: "36 35 98:0 / /mnt rw - cgroup cgroup rw,release_agent=/a\\054b\\134c\\040d\\011e\\012f,name=foo\\054bar,x\\075y=value",
            expect: Some((
                "/",
                "/mnt",
                "cgroup",
                None,
                &["rw", "release_agent=/a,b\\c d\te\nf", "name=foo,bar", "x=y=value"],
            )),
        },
        Case {
            name: "mangled: hash escape in fs_type",
            line: "36 35 98:0 / /mnt rw - a\\043b none rw",
            expect: Some(("/", "/mnt", "a#b", None, &["rw"])),
        },
        Case {
            name: "fs_type with subtype splits on the first dot",
            line: "36 35 98:0 / /mnt rw - fuse.sshfs none rw",
            expect: Some(("/", "/mnt", "fuse", Some("sshfs"), &["rw"])),
        },
        Case {
            name: "filesystem type before subtype is empty",
            line: "36 35 98:0 / /mnt rw - .sshfs none rw",
            expect: None,
        },
        Case {
            name: "filesystem subtype after type is empty",
            line: "36 35 98:0 / /mnt rw - fuse. none rw",
            expect: None,
        },
        Case {
            name: "optional fields after mount options are ignored",
            line: "36 35 98:0 / /mnt rw shared:1 master:2 propagate_from:2 unbindable - ext3 /dev/root rw",
            expect: Some(("/", "/mnt", "ext3", None, &["rw"])),
        },
        // --- rejections: every case must yield ParseMountError ---
        Case {
            name: "missing separator",
            line: "36 35 98:0 /mnt1 /mnt2 rw",
            expect: None,
        },
        Case {
            name: "too few fields before the separator",
            line: "36 35 98:0 /mnt1 - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "mount ID is not an integer",
            line: "thirtyfive 35 98:0 /mnt1 /mnt2 rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "parent ID is not an integer (also catches double spaces)",
            line: "36  35 98:0 /mnt1 /mnt2 rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "device field without a colon",
            line: "36 35 980 /mnt1 /mnt2 rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "device field is not numeric",
            line: "36 35 a:b /mnt1 /mnt2 rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "missing super options",
            line: "36 35 98:0 /mnt1 /mnt2 rw - ext3 /dev/root",
            expect: None,
        },
        Case {
            name: "missing mount source field",
            line: "36 35 98:0 / /mnt rw - tmpfs rw",
            expect: None,
        },
        Case {
            name: "unknown escape in mount_point",
            line: "36 35 98:0 /mnt1 /my\\052dir rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "truncated escape at the end of a field",
            line: "36 35 98:0 /mnt1 /my\\ rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "unknown escape in fs_type",
            line: "36 35 98:0 / /mnt rw - a\\999b none rw",
            expect: None,
        },
        Case {
            name: "filesystem-specific super option retains unknown escape",
            line: "36 35 98:0 / /mnt rw - cgroup cgroup rw,name=a\\999b\\054c\\",
            expect: Some(("/", "/mnt", "cgroup", None, &["rw", "name=a\\999b,c\\"])),
        },
        // --- empty mandatory fields: rejected even though the field
        //     counts line up (double spaces or a trailing space).
        Case {
            name: "empty mount root",
            line: "36 35 98:0  /mnt rw - ext3 /dev/root rw",
            expect: None,
        },
        Case {
            name: "empty mount options",
            line: "36 35 98:0 / /mnt  - ext3 none rw",
            expect: None,
        },
        Case {
            name: "empty filesystem type",
            line: "36 35 98:0 / /mnt rw -  none rw",
            expect: None,
        },
        Case {
            name: "empty super options (trailing space)",
            line: "36 35 98:0 / /mnt rw - ext3 none ",
            expect: None,
        },
    ];

    #[test]
    fn test_parse_mountinfo_line_table() {
        for case in CASES {
            let got = parse_mountinfo_line(case.line, 1);
            match (got, case.expect) {
                (Ok(record), Some(expect)) => {
                    assert_eq!(
                        record.mount_root,
                        PathBuf::from(expect.0),
                        "case `{}`",
                        case.name
                    );
                    assert_eq!(
                        record.mount_point,
                        PathBuf::from(expect.1),
                        "case `{}`",
                        case.name
                    );
                    assert_eq!(
                        record.fs_type,
                        (expect.2.to_string(), expect.3.map(str::to_string)),
                        "case `{}`",
                        case.name
                    );
                    let super_opts: Vec<Vec<u8>> =
                        expect.4.iter().map(|opt| opt.as_bytes().to_vec()).collect();
                    assert_eq!(record.super_opts, super_opts, "case `{}`", case.name);
                }
                (Err(err), None) => {
                    assert_eq!(err.line(), 1, "case `{}`: {err}", case.name);
                }
                (got, expect) => {
                    panic!("case `{}`: expected {:?}, got {:?}", case.name, expect, got)
                }
            }
        }
    }

    #[test]
    fn test_parse_mountinfo_stream() {
        let empty = parse_mountinfo("").unwrap();
        assert!(empty.records().is_empty());

        let v1 = "35 33 0:30 / /sys/fs/cgroup/systemd rw shared:11 - cgroup cgroup rw,name=systemd";
        let v2 = "47 44 0:30 / /sys/fs/cgroup rw shared:7 - cgroup2 cgroup2 rw";
        let plain = "36 35 98:0 / /mnt rw - tmpfs  rw,size=4096";
        let nsfs = "31 23 0:23 net:[4026534327] /run/netns/default rw - nsfs nsfs rw";

        // Hybrid input keeps cgroup, cgroup2, unrelated, and nsfs mounts
        // (whose `show_path` root is not a path at all).
        let table =
            parse_mountinfo_bytes(format!("{}\n{}\n{}\n{}\n", v1, v2, plain, nsfs).as_bytes())
                .unwrap();
        assert_eq!(table.records().len(), 4);
        assert_eq!(table.cgroup_mounts().len(), 1);
        assert_eq!(table.unified_mounts().len(), 1);

        // Errors carry the 1-based line number of the offending line.
        let bad = "36 35 98:0 /mnt1 /mnt2 rw";
        match parse_mountinfo(&format!("{}\n{}\n{}\n", v1, v2, bad)) {
            Err(err) => {
                assert_eq!(err.line(), 3);
            }
            other => panic!("expected a ParseMountError at line 3, got `{:?}`", other),
        }

        let non_utf8 =
            parse_mountinfo_bytes(b"36 35 98:0 /root-\xff /mount-\xfe rw - ext3 /dev/root rw\n")
                .unwrap();
        assert_eq!(
            non_utf8.records()[0].mount_root.as_os_str().as_bytes(),
            b"/root-\xff"
        );
        assert_eq!(
            non_utf8.records()[0].mount_point.as_os_str().as_bytes(),
            b"/mount-\xfe"
        );
    }

    #[test]
    fn test_parse_mountinfo_bytes_preserves_non_utf8_super_opts() {
        let input =
            b"36 35 98:0 / /merged rw - overlay overlay rw,lowerdir=/lower-\xff\\054x,upperdir=/upper\n\
47 44 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        let table = parse_mountinfo_bytes(input).unwrap();

        assert_eq!(table.records().len(), 2);
        assert_eq!(
            table.records()[0].super_opts,
            vec![
                b"rw".to_vec(),
                b"lowerdir=/lower-\xff,x".to_vec(),
                b"upperdir=/upper".to_vec(),
            ]
        );
        assert_eq!(table.unified_mounts().len(), 1);
    }

    #[test]
    fn test_parse_mount_error_variants_preserve_input() {
        match parse_mountinfo_bytes(b"36 35 98:0 / /bad\\052name rw - ext3 /dev/root rw")
            .unwrap_err()
        {
            ParseMountError::InvalidEscape {
                line: 1,
                field: "mount point",
                input,
            } => assert_eq!(input.as_bytes(), b"\\052"),
            other => panic!("expected an invalid mount-point escape, got {:?}", other),
        }

        match parse_mountinfo_bytes(b"36 35 980 / /mnt rw - ext3 /dev/root rw").unwrap_err() {
            ParseMountError::InvalidDevice { line: 1, input } => {
                assert_eq!(input.as_bytes(), b"980");
            }
            other => panic!("expected an invalid device, got {:?}", other),
        }
    }
}
