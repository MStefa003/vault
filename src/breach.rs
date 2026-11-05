//! Offline breached-password check against a local copy of the Have I Been
//! Pwned "Pwned Passwords" list.
//!
//! VaultRust never downloads anything. The user obtains the SHA-1 list
//! themselves (for example with the official `PwnedPasswordsDownloader` as a
//! single file ordered by hash) and points VaultRust at it. Each line is
//! `HEX40[:COUNT]`, sorted ascending by hash. The file is never read into
//! memory: every lookup is a binary search with a few dozen small reads, so a
//! 40 GB list works as well as a small one.
//!
//! Only SHA-1 hashes of passwords are compared; the passwords themselves
//! never leave memory.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

pub type Sha1Hash = [u8; 20];

/// Longest line we expect: 40 hex digits, ':', a count, CR LF.
const MAX_LINE: usize = 96;
/// Below this range size the search switches to a linear scan.
const LINEAR_SCAN: u64 = 4096;

pub fn sha1_of(password: &str) -> Sha1Hash {
    let mut h = Sha1::new();
    h.update(password.as_bytes());
    let out = h.finalize();
    let mut a = [0u8; 20];
    a.copy_from_slice(&out);
    a
}

/// A sorted SHA-1 list on disk.
pub struct BreachList {
    file: File,
    len: u64,
}

impl BreachList {
    pub fn open(path: &Path) -> io::Result<BreachList> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut list = BreachList { file, len };
        // Fail early on files that are obviously not a hash list.
        match list.line_at_or_after(0)? {
            Some((_, line)) if line.hash.is_some() => Ok(list),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a SHA-1 password list (expected lines like HASH:COUNT)",
            )),
        }
    }

    /// How often `hash` appears in the list, or `None` if it does not.
    pub fn lookup(&mut self, hash: &Sha1Hash) -> io::Result<Option<u64>> {
        // Invariant: a line with this hash, if any, starts in [lo, hi).
        let mut lo = 0u64;
        let mut hi = self.len;
        while hi - lo > LINEAR_SCAN {
            let mid = lo + (hi - lo) / 2;
            match self.line_at_or_after(mid)? {
                Some((start, line)) if start < hi => match line.hash {
                    Some(h) if h == *hash => return Ok(Some(line.count)),
                    Some(h) if h < *hash => lo = start + line.len as u64,
                    // Larger hash (or an unparsable line): look left.
                    _ => hi = mid,
                },
                _ => hi = mid,
            }
        }
        // Linear scan of the remaining range.
        let mut pos = lo;
        while pos < hi {
            let Some((start, line)) = self.line_at_or_after(pos)? else {
                break;
            };
            if start >= hi {
                break;
            }
            match line.hash {
                Some(h) if h == *hash => return Ok(Some(line.count)),
                Some(h) if h > *hash => break,
                _ => {}
            }
            pos = start + line.len as u64;
        }
        Ok(None)
    }

    /// The first line that starts at or after `offset`.
    fn line_at_or_after(&mut self, offset: u64) -> io::Result<Option<(u64, Line)>> {
        if offset >= self.len {
            return Ok(None);
        }
        // Read one byte early so we can tell whether `offset` is a line start.
        let read_from = offset.saturating_sub(1);
        self.file.seek(SeekFrom::Start(read_from))?;
        let mut buf = [0u8; MAX_LINE * 2];
        let n = read_up_to(&mut self.file, &mut buf)?;
        let buf = &buf[..n];
        let skip = if offset == 0 {
            0
        } else if buf.first() == Some(&b'\n') {
            1
        } else {
            match buf.iter().position(|&b| b == b'\n') {
                Some(p) => p + 1,
                None => return Ok(None),
            }
        };
        let start = read_from + skip as u64;
        if start >= self.len {
            return Ok(None);
        }
        let rest = &buf[skip..];
        let end = rest.iter().position(|&b| b == b'\n');
        let (text, len) = match end {
            Some(e) => (&rest[..e], e + 1),
            // Last line without a trailing newline, or a line longer than
            // the buffer (treated as unparsable).
            None => (rest, rest.len()),
        };
        Ok(Some((start, parse_line(text, len))))
    }
}

fn read_up_to(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

struct Line {
    hash: Option<Sha1Hash>,
    count: u64,
    /// Bytes including the newline.
    len: usize,
}

fn parse_line(text: &[u8], len: usize) -> Line {
    let text = text.strip_suffix(b"\r").unwrap_or(text);
    let hash = text.get(..40).and_then(|hex| {
        let mut out = [0u8; 20];
        for (i, pair) in hex.chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).ok()?;
            out[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(out)
    });
    let count = text
        .get(41..)
        .filter(|_| text.get(40) == Some(&b':'))
        .and_then(|c| std::str::from_utf8(c).ok())
        .and_then(|c| c.trim().parse().ok())
        .unwrap_or(1);
    Line {
        hash: hash.filter(|_| text.len() == 40 || text.get(40) == Some(&b':')),
        count,
        len,
    }
}

/// Look up every password; returns the breach count for each (same order).
pub fn check_passwords(
    path: &Path,
    passwords: &[Zeroizing<String>],
) -> io::Result<Vec<Option<u64>>> {
    let mut list = BreachList::open(path)?;
    passwords.iter().map(|p| list.lookup(&sha1_of(p))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn hex(h: &Sha1Hash) -> String {
        h.iter().map(|b| format!("{b:02X}")).collect()
    }

    fn write_list(lines: &[String], crlf: bool) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let nl = if crlf { "\r\n" } else { "\n" };
        for l in lines {
            write!(f, "{l}{nl}").unwrap();
        }
        f.flush().unwrap();
        f
    }

    #[test]
    fn finds_every_present_hash_and_rejects_absent_ones() {
        // Enough lines that the binary search (not just the linear scan) runs.
        let mut hashes: Vec<Sha1Hash> = (0..5000).map(|i| sha1_of(&format!("pw{i}"))).collect();
        hashes.sort();
        for crlf in [false, true] {
            let lines: Vec<String> = hashes
                .iter()
                .enumerate()
                .map(|(i, h)| format!("{}:{}", hex(h), i + 1))
                .collect();
            let f = write_list(&lines, crlf);
            let mut list = BreachList::open(f.path()).unwrap();
            for (i, h) in hashes.iter().enumerate() {
                assert_eq!(list.lookup(h).unwrap(), Some(i as u64 + 1), "line {i}");
            }
            for i in 0..500 {
                let absent = sha1_of(&format!("absent{i}"));
                assert_eq!(list.lookup(&absent).unwrap(), None);
            }
            assert_eq!(list.lookup(&[0u8; 20]).unwrap(), None);
            assert_eq!(list.lookup(&[0xff; 20]).unwrap(), None);
        }
    }

    #[test]
    fn hash_only_lines_and_known_password() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let mut hashes = vec![
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8".to_string(),
            "0000000000000000000000000000000000000001".to_string(),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string(),
        ];
        hashes.sort();
        let f = write_list(&hashes, false);
        let pws = [
            Zeroizing::new("password".to_string()),
            Zeroizing::new("correct horse battery staple".to_string()),
        ];
        assert_eq!(
            check_passwords(f.path(), &pws).unwrap(),
            vec![Some(1), None]
        );
    }

    #[test]
    fn rejects_files_that_are_not_hash_lists() {
        let f = write_list(&["hello world".to_string()], false);
        assert!(BreachList::open(f.path()).is_err());
        let empty = write_list(&[], false);
        assert!(BreachList::open(empty.path()).is_err());
    }
}
