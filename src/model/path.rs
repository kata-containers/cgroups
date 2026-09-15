// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::PathReason::{
    Absolute, CurrentComponent, EmptyComponent, NulByte, ParentComponent, Relative, Root, Separator,
};
use crate::error::{CoreError, PathReason};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::error::CoreResult;

/// A validated relative path identifying a cgroup within its hierarchy.
///
/// `CgroupPath` is the single source of truth for "which cgroup" across all
/// backends. Construction is the only fallible step: once a `CgroupPath`
/// exists, every backend operation that accepts it is infallible with respect
/// to path safety.
///
/// # Validity rules
///
/// - The path must be relative (no leading `/`).
/// - No component may be `..`, `.`, or empty.
/// - No component may contain a NUL byte (`\0`).
/// - The filesystem root (`/`) is rejected; empty input represents the
///   hierarchy root, equivalently to [`CgroupPath::root`].
/// - Components may contain colons (`:`) and need not be valid UTF-8.
///
/// The validated path is stored in canonical relative form and borrows as a
/// [`Path`] without allocation via [`CgroupPath::as_path`] or [`AsRef<Path>`],
/// including zero-copy component iteration through [`Path::components`].
///
/// No backend should accept a raw string or [`Path`] for cgroup mutation;
/// it should require a [`CgroupPath`] so that validation is centralized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CgroupPath {
    /// The validated canonical relative form; an empty path is the root.
    path: PathBuf,
}

impl CgroupPath {
    /// Create the `CgroupPath` representing the hierarchy root.
    ///
    /// The root is the identity element of [`CgroupPath::join`] and renders
    /// as an empty relative path. [`CgroupPath::new`] also accepts empty
    /// input as the hierarchy root; this constructor expresses that intent
    /// directly at call sites.
    pub fn root() -> CoreResult<Self> {
        Ok(Self {
            path: PathBuf::new(),
        })
    }

    /// Validate and construct a `CgroupPath` from any path-like input.
    ///
    /// Returns [`crate::error::CoreError::InvalidPath`] if the input is
    /// absolute, contains `..` or `.`, has empty components,
    /// contains a NUL byte, or is the filesystem root (`/`). An empty input
    /// represents the hierarchy root and succeeds identically to [`CgroupPath::root`].
    pub fn new<P: AsRef<Path>>(p: P) -> CoreResult<Self> {
        let path = p.as_ref();
        let input = path.to_path_buf();
        let operation = "CgroupPath::new";
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Self::root();
        }
        if bytes == b"/" {
            return Err(CoreError::InvalidPath {
                input,
                reason: Root,
                operation,
            });
        }
        if bytes.starts_with(b"/") {
            return Err(CoreError::InvalidPath {
                input,
                reason: Absolute,
                operation,
            });
        }
        for seg in bytes.split(|b| *b == b'/') {
            if let Some(reason) = segment_reason(seg) {
                return Err(CoreError::InvalidPath {
                    input,
                    reason,
                    operation,
                });
            }
        }
        Ok(Self { path: input })
    }

    /// Construct a `CgroupPath` from a `/proc/<pid>/cgroup` membership path.
    ///
    /// The input is the path field of a membership line exactly as it
    /// appears in `/proc/<pid>/cgroup`: it must begin with `/` (`/` alone
    /// denotes the hierarchy root, e.g. the `0::/` line). A single leading
    /// `/` is stripped and the remainder is validated with the same
    /// component rules as [`CgroupPath::new`] (no `..`, `.`, empty
    /// components, or NUL bytes), so a second leading `/` (e.g. `//a`)
    /// leaves an empty component and is rejected. Whole membership lines
    /// (e.g. `0::/user.slice`) are not accepted; pass the path field only.
    /// A kernel-reported path containing `..` (possible when observing a
    /// process outside the reader's cgroup namespace) is intentionally not
    /// convertible to a mutation-safe `CgroupPath`; keep that value as a
    /// [`crate::discovery::MembershipRecord`] observation instead.
    pub fn from_proc_membership<S: AsRef<OsStr>>(s: S) -> CoreResult<Self> {
        let bytes = s.as_ref().as_bytes();
        let input = Path::new(s.as_ref()).to_path_buf();
        let operation = "CgroupPath::from_proc_membership";
        if !bytes.starts_with(b"/") {
            return Err(CoreError::InvalidPath {
                input,
                reason: Relative,
                operation,
            });
        }
        let relative = &bytes[1..];
        if relative.is_empty() {
            return Self::root();
        }
        for seg in relative.split(|b| *b == b'/') {
            if let Some(reason) = segment_reason(seg) {
                return Err(CoreError::InvalidPath {
                    input,
                    reason,
                    operation,
                });
            }
        }
        Ok(Self {
            path: PathBuf::from(OsString::from_vec(relative.to_vec())),
        })
    }

    /// Construct a `CgroupPath` from a single component.
    ///
    /// Unlike [`CgroupPath::new`], the input must be exactly one component
    /// (one directory name): it must be non-empty, must not be `.` or `..`,
    /// and must not contain a `/` separator. A leading `/` is rejected as an
    /// absolute path. The result always has exactly one component.
    pub fn from_component<S: AsRef<OsStr>>(s: S) -> CoreResult<Self> {
        let bytes = s.as_ref().as_bytes();
        let input = Path::new(s.as_ref()).to_path_buf();
        let operation = "CgroupPath::from_component";
        if bytes.starts_with(b"/") {
            return Err(CoreError::InvalidPath {
                input,
                reason: Absolute,
                operation,
            });
        }
        if let Some(reason) = segment_reason(bytes) {
            return Err(CoreError::InvalidPath {
                input,
                reason,
                operation,
            });
        }
        if bytes.contains(&b'/') {
            return Err(CoreError::InvalidPath {
                input,
                reason: Separator,
                operation,
            });
        }
        Ok(Self { path: input })
    }

    /// Append a validated sub-path, returning a new `CgroupPath`.
    ///
    /// Both operands were validated at construction and are stored in
    /// canonical relative form, so appending one to the other satisfies
    /// every invariant by construction and is infallible.
    ///
    /// The root path is an identity on both sides (`root.join(x) == x`
    /// and `x.join(root) == x`), and the operation is associative.
    pub fn join(&self, sub: &CgroupPath) -> CgroupPath {
        if self.is_root() {
            return sub.clone();
        }
        if sub.is_root() {
            return self.clone();
        }
        let mut path = self.path.clone();
        path.push(&sub.path);
        Self { path }
    }

    /// Return the parent path, or `None` if this is the root.
    ///
    /// The returned `CgroupPath` is guaranteed to satisfy all validity
    /// invariants because the child was already validated.
    pub fn parent(&self) -> Option<CgroupPath> {
        let parent = self.path.parent()?;
        Some(Self {
            path: parent.to_path_buf(),
        })
    }

    /// Whether this path represents the hierarchy root.
    pub fn is_root(&self) -> bool {
        self.path.as_os_str().is_empty()
    }

    /// Borrow the validated path as a relative [`Path`].
    ///
    /// The borrow is zero-copy for every path, root included (the root is
    /// an empty `Path`). This lets a `CgroupPath` feed any API taking
    /// [`AsRef<Path>`] and enables zero-copy component iteration via
    /// [`Path::components`].
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// Convert this path into a systemd-compatible subgroup representation.
    ///
    /// Systemd encodes cgroup hierarchy positions using its own naming
    /// conventions (`.slice` / `.scope` suffixes, dash-escaped path
    /// components). This method will translate a validated `CgroupPath`
    /// into that representation for use with the systemd D-Bus manager
    /// interface.
    ///
    /// # Phase 2
    ///
    /// This is a placeholder for the systemd D-Bus integration rework.
    /// The translation rules depend on design decisions in Phase 2
    /// (slice nesting, scope naming, unit-name escaping) that have not
    /// been finalized yet.
    pub fn to_systemd_subgroup(&self) -> CoreResult<String> {
        unimplemented!(
            "CgroupPath::to_systemd_subgroup is a Phase 2 placeholder; \
             systemd unit-name translation is not yet implemented"
        )
    }
}

impl AsRef<Path> for CgroupPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// Classify a single raw path segment, returning why it is invalid.
fn segment_reason(seg: &[u8]) -> Option<PathReason> {
    if seg.is_empty() {
        Some(EmptyComponent)
    } else if seg == b".." {
        Some(ParentComponent)
    } else if seg == b"." {
        Some(CurrentComponent)
    } else if seg.contains(&0) {
        Some(NulByte)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PathReason;

    fn path(input: &str) -> CgroupPath {
        CgroupPath::new(input).unwrap_or_else(|e| panic!("`{}`: {}", input, e))
    }

    fn path_bytes(input: &[u8]) -> CgroupPath {
        CgroupPath::new(Path::new(OsStr::from_bytes(input)))
            .unwrap_or_else(|e| panic!("`{:?}`: {}", input, e))
    }

    /// Assert the rejection reason for an invalid input, along with the
    /// error context (original input echoed back, operation name).
    fn reject(input: &str) -> PathReason {
        match CgroupPath::new(input) {
            Err(CoreError::InvalidPath {
                input: echo,
                reason,
                operation,
            }) => {
                assert_eq!(operation, "CgroupPath::new");
                assert_eq!(echo, Path::new(input));
                reason
            }
            other => panic!("`{}`: expected InvalidPath, got `{:?}`", input, other),
        }
    }

    #[test]
    fn test_new_rejection_table() {
        struct Case {
            name: &'static str,
            input: &'static str,
            reason: PathReason,
        }
        const CASES: &[Case] = &[
            Case {
                name: "filesystem root",
                input: "/",
                reason: PathReason::Root,
            },
            Case {
                name: "absolute",
                input: "/a",
                reason: PathReason::Absolute,
            },
            Case {
                name: "absolute nested",
                input: "/a/b",
                reason: PathReason::Absolute,
            },
            Case {
                name: "double leading separator",
                input: "//a",
                reason: PathReason::Absolute,
            },
            Case {
                name: "double separator only is absolute, not root",
                input: "//",
                reason: PathReason::Absolute,
            },
            Case {
                name: "parent component leading",
                input: "../a",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "parent component trailing",
                input: "a/..",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "parent component alone",
                input: "..",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "parent component nested",
                input: "a/../b",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "current component leading",
                input: "./a",
                reason: PathReason::CurrentComponent,
            },
            Case {
                name: "current component alone",
                input: ".",
                reason: PathReason::CurrentComponent,
            },
            Case {
                name: "current component nested",
                input: "a/./b",
                reason: PathReason::CurrentComponent,
            },
            Case {
                name: "repeated separator",
                input: "a//b",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "trailing separator",
                input: "a/",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "nul byte in component",
                input: "a\0b",
                reason: PathReason::NulByte,
            },
            Case {
                name: "nul byte as whole input",
                input: "\0",
                reason: PathReason::NulByte,
            },
        ];
        for case in CASES {
            assert_eq!(reject(case.input), case.reason, "case `{}`", case.name);
        }
    }

    #[test]
    fn test_new_acceptance_table() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expect: &'static [&'static str],
        }
        const CASES: &[Case] = &[
            Case {
                name: "empty string is root",
                input: "",
                expect: &[],
            },
            Case {
                name: "single component",
                input: "a",
                expect: &["a"],
            },
            Case {
                name: "nested components",
                input: "docker/kata/a1",
                expect: &["docker", "kata", "a1"],
            },
            Case {
                name: "colon in component",
                input: "a:b/c",
                expect: &["a:b", "c"],
            },
            Case {
                name: "dot inside a component name",
                input: "foo.bar",
                expect: &["foo.bar"],
            },
            Case {
                name: "double dot inside a component name",
                input: "a..b",
                expect: &["a..b"],
            },
            Case {
                name: "leading double dot in a name",
                input: "..c",
                expect: &["..c"],
            },
            Case {
                name: "trailing double dot in a name",
                input: "c..",
                expect: &["c.."],
            },
        ];
        for case in CASES {
            let p = CgroupPath::new(case.input)
                .unwrap_or_else(|e| panic!("case `{}`: {}", case.name, e));
            let expect: Vec<OsString> = case.expect.iter().map(|s| OsString::from(*s)).collect();
            let got: Vec<OsString> = p
                .as_path()
                .components()
                .map(|c| c.as_os_str().to_os_string())
                .collect();
            assert_eq!(got, expect, "case `{}`", case.name);
            assert_eq!(p.is_root(), case.expect.is_empty(), "case `{}`", case.name);
        }
    }

    #[test]
    fn test_new_preserves_non_utf8_bytes() {
        let p = path_bytes(b"\xff\xfe/x");
        assert_eq!(p.as_path().as_os_str().as_bytes(), b"\xff\xfe/x");
        assert!(!p.is_root());

        let single = path_bytes(b"\xff");
        assert_eq!(single.as_path().as_os_str().as_bytes(), b"\xff");
    }

    #[test]
    fn test_root_canonical_form() {
        let root = CgroupPath::root().unwrap();
        assert!(root.is_root());
        assert!(!path("a").is_root());
        assert_ne!(root, path("a"));
        let empty = CgroupPath::new("").unwrap();
        assert!(empty.is_root());
        assert_eq!(root, empty);
    }

    #[test]
    fn test_join_table() {
        struct Case {
            name: &'static str,
            base: &'static str,
            sub: &'static str,
            expect: &'static str,
        }
        const CASES: &[Case] = &[
            Case {
                name: "append nested sub-path",
                base: "docker",
                sub: "kata/a1",
                expect: "docker/kata/a1",
            },
            Case {
                name: "deep append",
                base: "a/b",
                sub: "c/d/e",
                expect: "a/b/c/d/e",
            },
        ];
        for case in CASES {
            let got = path(case.base).join(&path(case.sub));
            assert_eq!(got, path(case.expect), "case `{}`", case.name);
        }

        let root = CgroupPath::root().unwrap();
        assert_eq!(path("docker").join(&root), path("docker"));
        assert_eq!(root.join(&path("kata/a1")), path("kata/a1"));
        assert_eq!(root.join(&root), root);
    }

    #[test]
    fn test_join_associativity() {
        let a = path("x");
        let b = path("y/z");
        let c = path("w");
        let left = a.join(&b).join(&c);
        let right = a.join(&b.join(&c));
        assert_eq!(left, right);
    }

    #[test]
    fn test_join_does_not_mutate_operands() {
        let a = path("docker");
        let b = path("kata/a1");
        let (a_before, b_before) = (a.clone(), b.clone());
        let _joined = a.join(&b);
        assert_eq!(a, a_before);
        assert_eq!(b, b_before);
    }

    #[test]
    fn test_join_preserves_bytes_and_colons() {
        let joined = path_bytes(b"\xff").join(&path_bytes(b"\xfe/x"));
        assert_eq!(joined.as_path().as_os_str().as_bytes(), b"\xff/\xfe/x");

        let colons = path("a:b").join(&path("c:d"));
        assert_eq!(colons, path("a:b/c:d"));
    }

    #[test]
    fn test_parent_table() {
        assert_eq!(CgroupPath::root().unwrap().parent(), None);
        assert_eq!(path("a").parent(), Some(CgroupPath::root().unwrap()));

        struct Case {
            name: &'static str,
            input: &'static str,
            expect: &'static str,
        }
        const CASES: &[Case] = &[
            Case {
                name: "two components",
                input: "a/b",
                expect: "a",
            },
            Case {
                name: "three components",
                input: "a/b/c",
                expect: "a/b",
            },
        ];
        for case in CASES {
            let got = path(case.input).parent();
            assert_eq!(got, Some(path(case.expect)), "case `{}`", case.name);
        }
    }

    #[test]
    fn test_parent_chain_reaches_root() {
        let mut current = path("a/b/c");
        let mut steps = 0;
        while let Some(parent) = current.parent() {
            current = parent;
            steps += 1;
        }
        assert_eq!(steps, 3);
        assert!(current.is_root());
    }

    #[test]
    fn test_parent_after_single_component_join() {
        let base = path("docker/kata");
        let leaf = path("a1");
        assert_eq!(base.join(&leaf).parent(), Some(base));
    }

    #[test]
    fn test_as_path_table() {
        assert_eq!(CgroupPath::root().unwrap().as_path(), Path::new(""));

        struct Case {
            name: &'static str,
            input: &'static str,
            expect: &'static str,
        }
        const CASES: &[Case] = &[
            Case {
                name: "single component",
                input: "a",
                expect: "a",
            },
            Case {
                name: "nested components",
                input: "docker/kata/a1",
                expect: "docker/kata/a1",
            },
            Case {
                name: "colon in component",
                input: "a:b/c",
                expect: "a:b/c",
            },
            Case {
                name: "dot inside a component name",
                input: "foo.bar",
                expect: "foo.bar",
            },
        ];
        for case in CASES {
            assert_eq!(
                path(case.input).as_path(),
                Path::new(case.expect),
                "case `{}`",
                case.name
            );
        }
    }

    #[test]
    fn test_as_ref_path() {
        let p = path("docker/kata/a1");
        let r: &Path = AsRef::as_ref(&p);
        assert_eq!(r, Path::new("docker/kata/a1"));
        assert_eq!(r, p.as_path());
    }

    #[test]
    fn test_as_path_preserves_bytes() {
        const INPUTS: &[&[u8]] = &[b"\xff\xfe/x", b"\xff", b"a:\xff/b"];
        for input in INPUTS {
            let p = path_bytes(input);
            assert_eq!(p.as_path().as_os_str().as_bytes(), *input);
            let reparsed =
                CgroupPath::new(p.as_path()).unwrap_or_else(|e| panic!("`{:?}`: {}", input, e));
            assert_eq!(reparsed, p);
        }
    }

    #[test]
    fn test_new_as_path_roundtrip() {
        const INPUTS: &[&str] = &[
            "",
            "a",
            "docker/kata/a1",
            "a:b/c",
            "foo.bar",
            "a..b",
            "..c",
            "c..",
        ];
        for input in INPUTS {
            let p = path(input);
            assert_eq!(p.as_path(), Path::new(*input), "borrow of `{}`", input);
            let reparsed =
                CgroupPath::new(p.as_path()).unwrap_or_else(|e| panic!("`{}`: {}", input, e));
            assert_eq!(reparsed, p, "round trip of `{}`", input);
        }
    }

    /// Assert the rejection reason for an invalid `from_component` input,
    /// along with the error context (original input echoed back, operation
    /// name).
    fn reject_component(input: &str) -> PathReason {
        match CgroupPath::from_component(input) {
            Err(CoreError::InvalidPath {
                input: echo,
                reason,
                operation,
            }) => {
                assert_eq!(operation, "CgroupPath::from_component");
                assert_eq!(echo, Path::new(input));
                reason
            }
            other => panic!("`{}`: expected InvalidPath, got `{:?}`", input, other),
        }
    }

    #[test]
    fn test_from_component() {
        assert_eq!(CgroupPath::from_component("init").unwrap(), path("init"));
        assert_eq!(CgroupPath::from_component("a:b").unwrap(), path("a:b"));
        assert_eq!(
            CgroupPath::from_component(OsStr::from_bytes(b"\xff")).unwrap(),
            path_bytes(b"\xff")
        );
        let single = CgroupPath::from_component("docker").unwrap();
        assert_eq!(single.as_path().components().count(), 1);

        struct Case {
            name: &'static str,
            input: &'static str,
            reason: PathReason,
        }
        const CASES: &[Case] = &[
            Case {
                name: "empty is not a component",
                input: "",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "current component",
                input: ".",
                reason: PathReason::CurrentComponent,
            },
            Case {
                name: "parent component",
                input: "..",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "absolute path",
                input: "/a",
                reason: PathReason::Absolute,
            },
            Case {
                name: "leading separator",
                input: "/",
                reason: PathReason::Absolute,
            },
            Case {
                name: "nested components",
                input: "a/b",
                reason: PathReason::Separator,
            },
            Case {
                name: "trailing separator",
                input: "a/",
                reason: PathReason::Separator,
            },
            Case {
                name: "separator after current component",
                input: "./a",
                reason: PathReason::Separator,
            },
            Case {
                name: "double separator",
                input: "a//b",
                reason: PathReason::Separator,
            },
            Case {
                name: "nul byte",
                input: "a\0b",
                reason: PathReason::NulByte,
            },
        ];
        for case in CASES {
            assert_eq!(
                reject_component(case.input),
                case.reason,
                "case `{}`",
                case.name
            );
        }
    }

    /// Assert the rejection reason for an invalid `from_proc_membership`
    /// input, along with the error context (original input echoed back,
    /// operation name).
    fn reject_membership(input: &str) -> PathReason {
        match CgroupPath::from_proc_membership(input) {
            Err(CoreError::InvalidPath {
                input: echo,
                reason,
                operation,
            }) => {
                assert_eq!(operation, "CgroupPath::from_proc_membership");
                assert_eq!(echo, Path::new(input));
                reason
            }
            other => panic!("`{}`: expected InvalidPath, got `{:?}`", input, other),
        }
    }

    #[test]
    fn test_from_proc_membership() {
        assert_eq!(
            CgroupPath::from_proc_membership("/").unwrap(),
            CgroupPath::root().unwrap()
        );
        assert_eq!(CgroupPath::from_proc_membership("/a").unwrap(), path("a"));
        assert_eq!(
            CgroupPath::from_proc_membership("/docker/kata/a1").unwrap(),
            path("docker/kata/a1")
        );
        assert_eq!(
            CgroupPath::from_proc_membership("/a:b/c").unwrap(),
            path("a:b/c")
        );
        assert_eq!(
            CgroupPath::from_proc_membership(OsStr::from_bytes(b"/\xff/x")).unwrap(),
            path_bytes(b"\xff/x")
        );

        struct Case {
            name: &'static str,
            input: &'static str,
            reason: PathReason,
        }
        const CASES: &[Case] = &[
            Case {
                name: "empty input",
                input: "",
                reason: PathReason::Relative,
            },
            Case {
                name: "relative single component",
                input: "a",
                reason: PathReason::Relative,
            },
            Case {
                name: "relative nested",
                input: "a/b",
                reason: PathReason::Relative,
            },
            Case {
                name: "double leading separator",
                input: "//a",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "double separator only",
                input: "//",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "leading parent component",
                input: "/..",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "parent component nested",
                input: "/a/../b",
                reason: PathReason::ParentComponent,
            },
            Case {
                name: "current component",
                input: "/./a",
                reason: PathReason::CurrentComponent,
            },
            Case {
                name: "repeated separator",
                input: "/a//b",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "trailing separator",
                input: "/a/",
                reason: PathReason::EmptyComponent,
            },
            Case {
                name: "nul byte",
                input: "/a\0b",
                reason: PathReason::NulByte,
            },
        ];
        for case in CASES {
            assert_eq!(
                reject_membership(case.input),
                case.reason,
                "case `{}`",
                case.name
            );
        }
    }
}
