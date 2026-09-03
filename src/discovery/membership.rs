// SPDX-License-Identifier: Apache-2.0 or MIT

//! Pure parser for membership records in the format of
//! `/proc/<pid>/cgroup`.
//!
//! The functions here transform supplied text into [`Membership`] values
//! and never perform I/O; reading the host belongs to the topology layer.

use std::path::PathBuf;

use crate::error::{CoreError, CoreResult, ParseSource};

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
    /// (e.g. `session:c1.scope`). Convert it to a validated path with
    /// [`crate::model::CgroupPath::from_proc_membership`].
    pub path: PathBuf,
}

/// The membership records parsed from one stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Membership {
    records: Vec<MembershipRecord>,
}

impl Membership {
    /// All parsed records, in input order.
    pub fn records(&self) -> &[MembershipRecord] {
        &self.records
    }

    /// The unified-hierarchy (`0::`) record, if present.
    pub fn unified(&self) -> Option<&MembershipRecord> {
        self.records.iter().find(|r| r.hierarchy_id == 0)
    }
}

/// Parse a membership stream into a [`Membership`].
///
/// # Contract
///
/// - Lines are split on their first two colons only, so colons inside
///   the cgroup path survive (e.g. the path of
///   `0::/user.slice/session:c1.scope` parses as
///   `/user.slice/session:c1.scope`).
/// - The hierarchy ID must parse as a [`u32`]; the controller list may
///   be empty (unified hierarchy).
/// - A malformed line returns [`crate::error::CoreError::ParseError`]
///   carrying the 1-based line number and the reason. Empty input
///   parses to an empty `Membership`.
pub fn parse_membership(input: &str) -> CoreResult<Membership> {
    let mut records = Vec::new();
    for (index, line) in input.lines().enumerate() {
        records.push(parse_membership_line(line, index + 1)?);
    }
    Ok(Membership { records })
}

/// Parse and validate a single membership line.
///
/// `line_no` is the 1-based position of `line` in the stream and is
/// reported in [`crate::error::CoreError::ParseError`] on failure.
///
/// Unlike mountinfo fields, the kernel does not escape the cgroup path:
/// colons and spaces can appear in it verbatim. The line is therefore
/// split on its first two colons only (`splitn(3, ':')`), and the third
/// field is taken as the whole remainder. The hierarchy ID must parse as
/// a [`u32`] (`0` denotes the unified hierarchy); the controller list is
/// comma-split and may be empty; the path must be non-empty and start
/// with `/`. The path is kept verbatim, without trimming, because it is
/// the final field and the kernel does not escape trailing whitespace
/// that a cgroup name may legitimately contain.
///
/// Crate-visible for the transitional manager shim; the stable public
/// surface is [`parse_membership`].
pub(crate) fn parse_membership_line(line: &str, line_no: usize) -> CoreResult<MembershipRecord> {
    let fields: Vec<&str> = line.splitn(3, ':').collect();
    if fields.len() != 3 {
        return Err(membership_error(
            line_no,
            format!(
                "expected `hierarchy-ID:controller-list:cgroup-path`, found {} colon-separated fields",
                fields.len()
            ),
        ));
    }
    let hierarchy_id = match fields[0].parse::<u32>() {
        Ok(id) => id,
        Err(_) => {
            return Err(membership_error(
                line_no,
                format!("hierarchy ID `{}` is not an integer", fields[0]),
            ))
        }
    };
    let controllers: Vec<String> = if fields[1].is_empty() {
        Vec::new()
    } else {
        let mut controllers = Vec::new();
        for controller in fields[1].split(',') {
            if controller.is_empty() {
                return Err(membership_error(
                    line_no,
                    format!("empty controller name in controller list `{}`", fields[1]),
                ));
            }
            controllers.push(controller.to_string());
        }
        controllers
    };
    let path = fields[2];
    if path.is_empty() {
        return Err(membership_error(
            line_no,
            "cgroup path field is empty".to_string(),
        ));
    }
    if !path.starts_with('/') {
        return Err(membership_error(
            line_no,
            format!("cgroup path `{}` does not start with `/`", path),
        ));
    }
    Ok(MembershipRecord {
        hierarchy_id,
        controllers,
        path: PathBuf::from(path),
    })
}

/// Build a membership parse error for `line_no`.
fn membership_error(line_no: usize, reason: String) -> CoreError {
    CoreError::ParseError {
        kind: ParseSource::Membership,
        line: line_no,
        reason,
    }
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
        // --- rejections: every case must yield ParseError { Membership } ---
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
                    assert!(
                        matches!(
                            err,
                            CoreError::ParseError {
                                kind: ParseSource::Membership,
                                line: 1,
                                ..
                            }
                        ),
                        "case `{}`: expected a membership ParseError, got `{}`",
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
            Err(CoreError::ParseError { kind, line, .. }) => {
                assert_eq!(kind, ParseSource::Membership);
                assert_eq!(line, 2);
            }
            other => panic!("expected a ParseError at line 2, got `{:?}`", other),
        }
    }
}
