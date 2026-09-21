// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Pure parser for membership records in the format of
//! `/proc/<pid>/cgroup`.
//!
//! The functions here transform supplied text or bytes into [`CgroupMembership`]
//! values and never perform I/O; reading the host belongs to the topology
//! layer.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::core::error::ParseMembershipError;

use super::byte_lines;

/// A single membership record from a `/proc/<pid>/cgroup` stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MembershipRecord {
    /// Hierarchy ID; `0` denotes the unified (cgroup v2) hierarchy.
    pub hierarchy_id: u32,
    /// Controllers bound to this hierarchy; empty for the unified
    /// hierarchy.
    pub controllers: Vec<String>,
    /// The process's cgroup path within that hierarchy, exactly as it
    /// appears in the record: it begins with `/` and may contain colons
    /// (e.g. `session:c1.scope`). When the target process is outside the
    /// reader's cgroup namespace, the path may begin with one or more `..`
    /// components and must remain an observation rather than a mutation path.
    pub path: PathBuf,
}

/// The membership records parsed from one stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupMembership {
    records: Vec<MembershipRecord>,
}

impl CgroupMembership {
    /// All parsed records, in input order.
    pub fn records(&self) -> &[MembershipRecord] {
        &self.records
    }

    /// The unified-hierarchy (`0::`) record, if present.
    pub fn unified(&self) -> Option<&MembershipRecord> {
        self.records.iter().find(|r| r.hierarchy_id == 0)
    }
}

/// Parse a membership stream into a [`CgroupMembership`].
///
/// # Contract
///
/// - Lines are split on their first two colons only, so colons inside
///   the cgroup path survive (e.g. the path of
///   `0::/user.slice/session:c1.scope` parses as
///   `/user.slice/session:c1.scope`).
/// - The hierarchy ID must parse as a [`u32`]; the controller list may
///   be empty (unified hierarchy).
/// - Hierarchy IDs and controller bindings must be unique across the
///   stream, so consumers cannot observe conflicting first/last-wins views.
/// - A malformed line returns a [`ParseMembershipError`] variant
///   carrying the 1-based line number and relevant input. Empty input
///   parses to an empty `CgroupMembership`.
pub fn parse_membership(input: &str) -> Result<CgroupMembership, ParseMembershipError> {
    parse_membership_bytes(input.as_bytes())
}

/// Parse a membership stream from its procfs byte representation.
///
/// Unlike [`parse_membership`], this entry point can represent non-UTF-8
/// cgroup names. It also splits records only on the kernel's `\n` delimiter;
/// a trailing carriage return is path data rather than part of a CRLF line
/// ending.
pub fn parse_membership_bytes(input: &[u8]) -> Result<CgroupMembership, ParseMembershipError> {
    let mut records = Vec::new();
    let mut hierarchy_lines = HashMap::new();
    let mut controller_lines = HashMap::new();

    for (index, line) in byte_lines(input).enumerate() {
        let line_no = index + 1;
        let record = parse_membership_line_bytes(line, line_no)?;

        if let Some(first_line) = hierarchy_lines.insert(record.hierarchy_id, line_no) {
            return Err(ParseMembershipError::DuplicateHierarchyId {
                line: line_no,
                hierarchy_id: record.hierarchy_id,
                first_line,
            });
        }

        for controller in &record.controllers {
            if let Some(first_line) = controller_lines.insert(controller.clone(), line_no) {
                return Err(ParseMembershipError::DuplicateController {
                    line: line_no,
                    controller: controller.clone(),
                    first_line,
                });
            }
        }

        records.push(record);
    }
    Ok(CgroupMembership { records })
}

/// Parse and validate a single membership line.
///
/// `line_no` is the 1-based position of `line` in the stream and is
/// reported in [`ParseMembershipError`] on failure.
///
/// Unlike mountinfo fields, the kernel does not escape the cgroup path:
/// colons and spaces can appear in it verbatim. The line is therefore
/// split on its first two colons only (`splitn(3, ':')`), and the third
/// field is taken as the whole remainder. The hierarchy ID must parse as
/// a [`u32`] (`0` denotes the unified hierarchy); the controller list is
/// comma-split and may be empty; the path must be non-empty and start
/// with `/`. Empty and current-directory components are rejected, while
/// parent components are retained because the kernel emits them when the
/// target process is outside the reader's cgroup namespace. The path is
/// kept verbatim, without trimming, because it is the final field and the
/// kernel does not escape trailing whitespace that a cgroup name may
/// legitimately contain.
///
/// Crate-visible for focused compatibility tests; the stable public surfaces
/// are [`parse_membership`] and [`parse_membership_bytes`].
#[cfg(test)]
pub(crate) fn parse_membership_line(
    line: &str,
    line_no: usize,
) -> Result<MembershipRecord, ParseMembershipError> {
    parse_membership_line_bytes(line.as_bytes(), line_no)
}

/// Byte-oriented implementation of [`parse_membership_line`].
pub(crate) fn parse_membership_line_bytes(
    line: &[u8],
    line_no: usize,
) -> Result<MembershipRecord, ParseMembershipError> {
    let fields: Vec<&[u8]> = line.splitn(3, |byte| *byte == b':').collect();
    if fields.len() != 3 {
        return Err(ParseMembershipError::MissingFields {
            line: line_no,
            found: fields.len(),
        });
    }
    let hierarchy_text = std::str::from_utf8(fields[0]).map_err(|_| {
        ParseMembershipError::InvalidHierarchyEncoding {
            line: line_no,
            input: OsStr::from_bytes(fields[0]).to_os_string(),
        }
    })?;
    let hierarchy_id = match hierarchy_text.parse::<u32>() {
        Ok(id) => id,
        Err(_) => {
            return Err(ParseMembershipError::InvalidHierarchyId {
                line: line_no,
                input: OsStr::from_bytes(fields[0]).to_os_string(),
            })
        }
    };
    let controllers: Vec<String> = if fields[1].is_empty() {
        Vec::new()
    } else {
        let mut controllers = Vec::new();
        for controller in fields[1].split(|byte| *byte == b',') {
            if controller.is_empty() {
                return Err(ParseMembershipError::EmptyController {
                    line: line_no,
                    list: OsStr::from_bytes(fields[1]).to_os_string(),
                });
            }
            let controller = std::str::from_utf8(controller).map_err(|_| {
                ParseMembershipError::InvalidControllerEncoding {
                    line: line_no,
                    input: OsStr::from_bytes(controller).to_os_string(),
                }
            })?;
            controllers.push(controller.to_string());
        }
        controllers
    };
    // Semantic validation:
    // - hierarchy ID 0 denotes unified hierarchy and must have an empty controller list
    // - hierarchy ID > 0 denotes v1 hierarchy and must have a non-empty controller list
    if hierarchy_id == 0 {
        if !controllers.is_empty() {
            return Err(ParseMembershipError::UnexpectedUnifiedControllers {
                line: line_no,
                controllers: OsStr::from_bytes(fields[1]).to_os_string(),
            });
        }
    } else if controllers.is_empty() {
        return Err(ParseMembershipError::MissingV1Controllers {
            line: line_no,
            hierarchy_id,
        });
    }

    let path = fields[2];
    if path.is_empty() {
        return Err(ParseMembershipError::EmptyPath { line: line_no });
    }
    if !path.starts_with(b"/") {
        return Err(ParseMembershipError::RelativePath {
            line: line_no,
            input: PathBuf::from(OsStr::from_bytes(path)),
        });
    }

    validate_membership_path(path, line_no)?;

    Ok(MembershipRecord {
        hierarchy_id,
        controllers,
        path: PathBuf::from(OsStr::from_bytes(path)),
    })
}

/// Validate the structure of an observed membership path without treating it
/// as a path that is safe to join beneath a writable cgroupfs root.
fn validate_membership_path(path: &[u8], line_no: usize) -> Result<(), ParseMembershipError> {
    if path == b"/" {
        return Ok(());
    }

    for component in path[1..].split(|byte| *byte == b'/') {
        let error = if component.is_empty() {
            Some(ParseMembershipError::EmptyPathComponent {
                line: line_no,
                input: PathBuf::from(OsStr::from_bytes(path)),
            })
        } else if component == b"." {
            Some(ParseMembershipError::CurrentPathComponent {
                line: line_no,
                input: PathBuf::from(OsStr::from_bytes(path)),
            })
        } else if component.contains(&0) {
            Some(ParseMembershipError::NulPathComponent {
                line: line_no,
                input: PathBuf::from(OsStr::from_bytes(path)),
            })
        } else {
            None
        };

        if let Some(error) = error {
            return Err(error);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned expectation for a parsed membership line: hierarchy ID,
    /// controller names, cgroup path.
    type Expect = (u32, &'static [&'static str], &'static str);

    struct Case {
        name: &'static str,
        line: &'static str,
        expect: Option<Expect>,
    }

    const CASES: &[Case] = &[
        Case {
            name: "v1: multiple controllers (cgroups(7) example)",
            line: "5:cpuacct,cpu,cpuset:/daemons",
            expect: Some((5, &["cpuacct", "cpu", "cpuset"], "/daemons")),
        },
        Case {
            name: "v1: single controller",
            line: "10:memory:/user.slice",
            expect: Some((10, &["memory"], "/user.slice")),
        },
        Case {
            name: "v1: named systemd hierarchy",
            line: "1:name=systemd:/system.slice/sshd.service",
            expect: Some((1, &["name=systemd"], "/system.slice/sshd.service")),
        },
        Case {
            name: "v2: unified scope path",
            line: "0::/user.slice/session-1.scope",
            expect: Some((0, &[], "/user.slice/session-1.scope")),
        },
        Case {
            name: "v2: hierarchy root",
            line: "0::/",
            expect: Some((0, &[], "/")),
        },
        Case {
            name: "colon inside the path survives",
            line: "0::/user.slice/session:c1.scope",
            expect: Some((0, &[], "/user.slice/session:c1.scope")),
        },
        Case {
            name: "multiple colons inside the path survive",
            line: "0::/a:b:c",
            expect: Some((0, &[], "/a:b:c")),
        },
        Case {
            name: "space inside the path is not escaped or trimmed",
            line: "0::/my dir",
            expect: Some((0, &[], "/my dir")),
        },
        // --- rejections: every case must yield ParseMembershipError ---
        Case {
            name: "no colon separators",
            line: "5cpuacct",
            expect: None,
        },
        Case {
            name: "missing cgroup path",
            line: "5:cpuacct",
            expect: None,
        },
        Case {
            name: "hierarchy ID is not an integer",
            line: "x:memory:/daemons",
            expect: None,
        },
        Case {
            name: "empty cgroup path",
            line: "5:memory:",
            expect: None,
        },
        Case {
            name: "path does not start with /",
            line: "5:memory:daemons",
            expect: None,
        },
        Case {
            name: "empty controller name in the list",
            line: "5:memory,,cpu:/daemons",
            expect: None,
        },
        Case {
            name: "blank line",
            line: "",
            expect: None,
        },
        Case {
            name: "v2 with non-empty controller list",
            line: "0:cpu:/x",
            expect: None,
        },
        Case {
            name: "v1 with empty controller list",
            line: "5::/x",
            expect: None,
        },
        Case {
            name: "namespace-relative path retains parent component",
            line: "0::/a/../b",
            expect: Some((0, &[], "/a/../b")),
        },
        Case {
            name: "target outside cgroup namespace",
            line: "0::/../../sibling.scope",
            expect: Some((0, &[], "/../../sibling.scope")),
        },
        Case {
            name: "path contains current component",
            line: "0::/./a",
            expect: None,
        },
        Case {
            name: "path contains empty component",
            line: "0::/a//b",
            expect: None,
        },
    ];

    #[test]
    fn test_parse_membership_line_table() {
        for case in CASES {
            let got = parse_membership_line(case.line, 1);
            match (got, case.expect) {
                (Ok(record), Some(expect)) => {
                    assert_eq!(record.hierarchy_id, expect.0, "case `{}`", case.name);
                    let controllers: Vec<String> =
                        expect.1.iter().map(|name| name.to_string()).collect();
                    assert_eq!(record.controllers, controllers, "case `{}`", case.name);
                    assert_eq!(record.path, PathBuf::from(expect.2), "case `{}`", case.name);
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
    fn test_parse_membership_stream() {
        let empty = parse_membership("").unwrap();
        assert!(empty.records().is_empty());
        assert!(empty.unified().is_none());

        let v1 = "5:cpuacct,cpu,cpuset:/daemons";
        let v2 = "0::/user.slice/session-1.scope";

        // Hybrid input keeps both records; `unified()` selects the `0::` one.
        let membership = parse_membership(&format!("{}\n{}\n", v1, v2)).unwrap();
        assert_eq!(membership.records().len(), 2);
        let unified = membership.unified().expect("unified record missing");
        assert_eq!(unified.hierarchy_id, 0);
        assert_eq!(unified.path, PathBuf::from("/user.slice/session-1.scope"));

        // v1-only input has no unified record.
        let v1_only = parse_membership(&format!("{}\n", v1)).unwrap();
        assert!(v1_only.unified().is_none());

        // Errors carry the 1-based line number of the offending line.
        let bad = "5:cpuacct";
        match parse_membership(&format!("{}\n{}\n", v2, bad)) {
            Err(err) => {
                assert_eq!(err.line(), 2);
            }
            other => panic!(
                "expected a ParseMembershipError at line 2, got `{:?}`",
                other
            ),
        }

        // `str::lines()` would treat the final CRLF as one line ending and
        // silently remove the carriage return from the cgroup name. Procfs
        // records are LF-delimited, so the CR is path data and must survive.
        let trailing_cr = parse_membership("0::/ends-with-cr\r\n").unwrap();
        assert_eq!(
            trailing_cr.records()[0].path.as_os_str().as_bytes(),
            b"/ends-with-cr\r"
        );

        let non_utf8 = parse_membership_bytes(b"0::/non-utf8-\xff\n").unwrap();
        assert_eq!(
            non_utf8.records()[0].path.as_os_str().as_bytes(),
            b"/non-utf8-\xff"
        );

        match parse_membership("0::/first\n0::/second\n") {
            Err(ParseMembershipError::DuplicateHierarchyId {
                line: 2,
                hierarchy_id: 0,
                first_line: 1,
            }) => {}
            other => panic!("expected a duplicate-hierarchy error, got `{:?}`", other),
        }

        match parse_membership("5:cpu:/first\n6:cpu:/second\n") {
            Err(ParseMembershipError::DuplicateController {
                line: 2,
                controller,
                first_line: 1,
            }) if controller == "cpu" => {}
            other => panic!("expected a duplicate-controller error, got `{:?}`", other),
        }
    }

    #[test]
    fn test_parse_membership_error_variants_preserve_input() {
        match parse_membership_bytes(b"0::/a//b").unwrap_err() {
            ParseMembershipError::EmptyPathComponent { line: 1, input } => {
                assert_eq!(input.as_os_str().as_bytes(), b"/a//b");
            }
            other => panic!("expected an empty path component, got {:?}", other),
        }

        match parse_membership_bytes(b"5:cpu-\xff:/x").unwrap_err() {
            ParseMembershipError::InvalidControllerEncoding { line: 1, input } => {
                assert_eq!(input.as_bytes(), b"cpu-\xff");
            }
            other => panic!("expected an invalid controller encoding, got {:?}", other),
        }
    }
}
