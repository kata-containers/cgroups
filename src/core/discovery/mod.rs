// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Host discovery: pure parsers for kernel text formats.
//!
//! The parsers in this module transform supplied text or bytes into
//! [`CgroupMountTable`] and [`CgroupMembership`] values and never perform I/O. Reading the host
//! (`/proc` and the cgroup filesystem) belongs to the topology layer that
//! assembles a snapshot from these pure results.

pub mod membership;
pub mod mountinfo;

pub use membership::{
    parse_membership, parse_membership_bytes, CgroupMembership, MembershipRecord,
};
pub use mountinfo::{parse_mountinfo, parse_mountinfo_bytes, CgroupMountTable, MountRecord};

/// Iterate newline-delimited procfs records without applying text-mode CRLF
/// normalization.
///
/// A final newline terminates the preceding record and does not create an
/// extra empty record. An empty record before that final newline is retained,
/// so malformed blank lines are still reported by the format parser.
pub(crate) fn byte_lines(input: &[u8]) -> ByteLines<'_> {
    ByteLines { remaining: input }
}

pub(crate) struct ByteLines<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for ByteLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        match self.remaining.iter().position(|byte| *byte == b'\n') {
            Some(end) => {
                let (line, rest) = self.remaining.split_at(end);
                self.remaining = &rest[1..];
                Some(line)
            }
            None => {
                let line = self.remaining;
                self.remaining = &[];
                Some(line)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_lines() {
        assert_eq!(byte_lines(b"").collect::<Vec<_>>(), Vec::<&[u8]>::new());
        assert_eq!(byte_lines(b"abc").collect::<Vec<_>>(), vec![&b"abc"[..]]);
        assert_eq!(byte_lines(b"abc\n").collect::<Vec<_>>(), vec![&b"abc"[..]]);
        assert_eq!(
            byte_lines(b"abc\ndef\n").collect::<Vec<_>>(),
            vec![&b"abc"[..], &b"def"[..]]
        );
        assert_eq!(
            byte_lines(b"abc\n\ndef\n").collect::<Vec<_>>(),
            vec![&b"abc"[..], &b""[..], &b"def"[..]]
        );
        assert_eq!(
            byte_lines(b"abc\r\ndef\n").collect::<Vec<_>>(),
            vec![&b"abc\r"[..], &b"def"[..]]
        );
        assert_eq!(byte_lines(b"\n").collect::<Vec<_>>(), vec![&b""[..]]);
    }
}
