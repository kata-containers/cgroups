// SPDX-License-Identifier: Apache-2.0 or MIT

//! Pure parser for mountinfo records in the format described by proc(5).
//!
//! The functions here transform supplied text into [`MountTable`] values
//! and never perform I/O; reading `/proc/self/mountinfo` belongs to the
//! topology layer.

use std::path::PathBuf;

use crate::error::{CoreError, CoreResult, ParseSource};

/// A single mount record with its escaped fields decoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MountRecord {
    /// Root of the mount within the mounted filesystem.
    pub mount_root: PathBuf,
    /// Pathname of the mount point relative to the process's root.
    pub mount_point: PathBuf,
    /// Filesystem type: main type with an optional subtype.
    pub fs_type: (String, Option<String>),
    /// Superblock options.
    pub super_opts: Vec<String>,
}

/// The mounts parsed from a mountinfo stream.
///
/// The table retains every parsed mount, not only cgroup mounts; use
/// [`MountTable::cgroup_mounts`] and [`MountTable::unified_mounts`] to
/// select the cgroup-relevant subsets. Hybrid layouts therefore keep both
/// their cgroup and cgroup2 mounts instead of picking one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountTable {
    records: Vec<MountRecord>,
}

impl MountTable {
    /// All parsed mount records, in input order.
    pub fn records(&self) -> &[MountRecord] {
        &self.records
    }

    /// cgroup v1 mounts, in input order.
    pub fn cgroup_mounts(&self) -> Vec<&MountRecord> {
        self.records
            .iter()
            .filter(|record| record.fs_type.0 == "cgroup")
            .collect()
    }

    /// cgroup v2 (unified) mounts, in input order.
    pub fn unified_mounts(&self) -> Vec<&MountRecord> {
        self.records
            .iter()
            .filter(|record| record.fs_type.0 == "cgroup2")
            .collect()
    }
}

/// Parse a mountinfo stream into a [`MountTable`].
///
/// # Contract
///
/// - Every line is validated; a malformed line returns
///   [`crate::error::CoreError::ParseError`] carrying the 1-based line
///   number and the reason. Empty input parses to an empty table.
/// - Escaped fields are decoded per proc(5) and `fs/proc_namespace.c`:
///   `\040` (space), `\011` (tab), `\012` (newline), and `\134`
///   (backslash), plus `\043` (`#`) in the mangled filesystem-type and
///   source fields. An unknown or truncated escape is an error, never
///   silent passthrough.
/// - All mounts are retained, not only cgroup mounts.
pub fn parse_mountinfo(input: &str) -> CoreResult<MountTable> {
    let mut records = Vec::new();
    for (index, line) in input.lines().enumerate() {
        records.push(parse_mountinfo_line(line, index + 1)?);
    }
    Ok(MountTable { records })
}

/// proc(5) escape sequences for the `mount_root` and `mount_point`
/// fields (`fs/proc_namespace.c` escapes `" \t\n\\"`).
const PATH_ESCAPES: [(&str, char); 4] = [
    ("\\040", ' '),
    ("\\011", '\t'),
    ("\\012", '\n'),
    ("\\134", '\\'),
];

/// Escape sequences for the mangled filesystem-type and source fields,
/// which additionally escape `#` (`fs/proc_namespace.c`: `mangle`).
const MANGLED_ESCAPES: [(&str, char); 5] = [
    ("\\040", ' '),
    ("\\011", '\t'),
    ("\\012", '\n'),
    ("\\134", '\\'),
    ("\\043", '#'),
];

/// Parse and validate a single mountinfo line.
///
/// `line_no` is the 1-based position of `line` in the stream and is
/// reported in [`crate::error::CoreError::ParseError`] on failure.
///
/// The line is split on the first literal ` - `: escaped fields can never
/// contain it unescaped. The mount ID, parent ID, and `major:minor`
/// device field are validated as integers. `mount_root` is escape-decoded
/// but otherwise opaque: filesystems implement `show_path` themselves
/// and may emit non-path tokens (nsfs emits `net:[4026534327]`), so no
/// absolute-path assumption is made. `mount_point` is escape-decoded and
/// must be an absolute path, because the VFS (not the filesystem)
/// generates it. Every mandatory field — mount root, mount options,
/// filesystem type, mount source, and super options — must be non-empty;
/// the mount root is required to be non-empty only, never absolute. The
/// mount options and the optional fields (`shared:` and friends) are not
/// retained; per proc(5), unrecognized optional fields are ignored. The
/// filesystem type and source are decoded with the mangled escape set,
/// and the type is split on its first `.` into main type and optional
/// subtype. Super options are comma-split into
/// [`MountRecord::super_opts`]; they are taken as the remainder of the
/// line because the kernel does not escape them (a `release_agent=`
/// path may contain spaces).
///
/// Crate-visible for the transitional `hierarchies` and manager shims;
/// the stable public surface is [`parse_mountinfo`].
pub(crate) fn parse_mountinfo_line(line: &str, line_no: usize) -> CoreResult<MountRecord> {
    let (shared, fs_part) = match line.split_once(" - ") {
        Some(parts) => parts,
        None => {
            return Err(CoreError::ParseError {
                kind: ParseSource::Mountinfo,
                line: line_no,
                reason: "missing ` - ` separator between the mount and filesystem fields"
                    .to_string(),
            })
        }
    };

    let shared_fields: Vec<&str> = shared.split(' ').collect();
    if shared_fields.len() < 6 {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: format!(
                "expected at least 6 fields before the separator, found {}",
                shared_fields.len()
            ),
        });
    }
    if shared_fields[0].parse::<u32>().is_err() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: format!("mount ID `{}` is not an integer", shared_fields[0]),
        });
    }
    if shared_fields[1].parse::<u32>().is_err() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: format!("parent ID `{}` is not an integer", shared_fields[1]),
        });
    }
    let (major, minor) = match shared_fields[2].split_once(':') {
        Some(ids) => ids,
        None => {
            return Err(CoreError::ParseError {
                kind: ParseSource::Mountinfo,
                line: line_no,
                reason: format!(
                    "device field `{}` is not `<major>:<minor>`",
                    shared_fields[2]
                ),
            })
        }
    };
    if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: format!(
                "device field `{}` is not `<major>:<minor>`",
                shared_fields[2]
            ),
        });
    }

    if shared_fields[3].is_empty() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: "mount root field is empty".to_string(),
        });
    }
    if shared_fields[5].is_empty() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: "mount options field is empty".to_string(),
        });
    }

    let mount_root = decode_escaped_field(shared_fields[3], &PATH_ESCAPES, line_no)?;
    let mount_point = decode_escaped_field(shared_fields[4], &PATH_ESCAPES, line_no)?;
    if !mount_point.starts_with('/') {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: format!("mount point `{}` is not an absolute path", mount_point),
        });
    }

    let fs_fields: Vec<&str> = fs_part.splitn(3, ' ').collect();
    if fs_fields.len() != 3 {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: "expected filesystem type, source, and super options after the separator"
                .to_string(),
        });
    }
    if fs_fields[0].is_empty() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: "filesystem type field is empty".to_string(),
        });
    }
    if fs_fields[1].is_empty() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: "mount source field is empty".to_string(),
        });
    }
    if fs_fields[2].trim().is_empty() {
        return Err(CoreError::ParseError {
            kind: ParseSource::Mountinfo,
            line: line_no,
            reason: "super options field is empty".to_string(),
        });
    }
    let fs_type_raw = decode_escaped_field(fs_fields[0], &MANGLED_ESCAPES, line_no)?;
    let (fs_type, fs_subtype) = match fs_type_raw.split_once('.') {
        Some((fs_type, subtype)) => (fs_type.to_string(), Some(subtype.to_string())),
        None => (fs_type_raw, None),
    };
    // The mount source must be well-formed (its escapes are validated)
    // but is not retained in a `MountRecord`.
    decode_escaped_field(fs_fields[1], &MANGLED_ESCAPES, line_no)?;

    let super_opts: Vec<String> = fs_fields[2].trim().split(',').map(String::from).collect();

    Ok(MountRecord {
        mount_root: PathBuf::from(mount_root),
        mount_point: PathBuf::from(mount_point),
        fs_type: (fs_type, fs_subtype),
        super_opts,
    })
}

/// Decode one escaped mountinfo field.
///
/// Every backslash must introduce one of the sequences in `escapes`; an
/// unknown or truncated escape is a parse error, never silent
/// passthrough.
fn decode_escaped_field(raw: &str, escapes: &[(&str, char)], line_no: usize) -> CoreResult<String> {
    let bytes = raw.as_bytes();
    let mut decoded = String::with_capacity(raw.len());
    let mut plain = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        decoded.push_str(&raw[plain..i]);
        let replacement = match raw.get(i..i + 4) {
            Some(escape) => escapes
                .iter()
                .find_map(|(sequence, ch)| (*sequence == escape).then_some(*ch)),
            None => None,
        };
        let replacement = match replacement {
            Some(ch) => ch,
            None => {
                return Err(CoreError::ParseError {
                    kind: ParseSource::Mountinfo,
                    line: line_no,
                    reason: format!(
                        "unknown or truncated escape `{}` in an escaped field",
                        raw[i..].chars().take(4).collect::<String>()
                    ),
                })
            }
        };
        decoded.push(replacement);
        i += 4;
        plain = i;
    }
    decoded.push_str(&raw[plain..]);
    Ok(decoded)
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
            name: "optional fields after mount options are ignored",
            line: "36 35 98:0 / /mnt rw shared:1 master:2 propagate_from:2 unbindable - ext3 /dev/root rw",
            expect: Some(("/", "/mnt", "ext3", None, &["rw"])),
        },
        // --- rejections: every case must yield ParseError { Mountinfo } ---
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
            name: "empty mount source",
            line: "36 35 98:0 / /mnt rw - ext3  rw",
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
                    let super_opts: Vec<String> =
                        expect.4.iter().map(|opt| opt.to_string()).collect();
                    assert_eq!(record.super_opts, super_opts, "case `{}`", case.name);
                }
                (Err(err), None) => {
                    assert!(
                        matches!(
                            err,
                            CoreError::ParseError {
                                kind: ParseSource::Mountinfo,
                                line: 1,
                                ..
                            }
                        ),
                        "case `{}`: expected a mountinfo ParseError, got `{}`",
                        case.name,
                        err
                    );
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
        let plain = "36 35 98:0 / /mnt rw - ext3 /dev/root rw";
        let nsfs = "31 23 0:23 net:[4026534327] /run/netns/default rw - nsfs nsfs rw";

        // Hybrid input keeps cgroup, cgroup2, unrelated, and nsfs mounts
        // (whose `show_path` root is not a path at all).
        let table = parse_mountinfo(&format!("{}\n{}\n{}\n{}\n", v1, v2, plain, nsfs)).unwrap();
        assert_eq!(table.records().len(), 4);
        assert_eq!(table.cgroup_mounts().len(), 1);
        assert_eq!(table.unified_mounts().len(), 1);

        // Errors carry the 1-based line number of the offending line.
        let bad = "36 35 98:0 /mnt1 /mnt2 rw";
        match parse_mountinfo(&format!("{}\n{}\n{}\n", v1, v2, bad)) {
            Err(CoreError::ParseError { kind, line, .. }) => {
                assert_eq!(kind, ParseSource::Mountinfo);
                assert_eq!(line, 3);
            }
            other => panic!("expected a ParseError at line 3, got `{:?}`", other),
        }
    }
}
