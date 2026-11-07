//! Strict DER reading and writing, PEM framing and base64, for the key-file
//! formats (PKCS#1, SEC1, PKCS#8, X.509 subject names).
//!
//! The reader is a small tag-length-value cursor that enforces DER's
//! canonical rules (definite minimal lengths, canonical `INTEGER`s, no
//! high-tag-number form), which is all the ASN.1 these formats need. Base64
//! is the constant-time [`base64ct`] implementation, so decoding a private
//! key's PEM body does not leak its bytes through table lookups.

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::Encoding;

/// Universal tag numbers used by the key formats.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// UTF8String.
    pub const UTF8_STRING: u8 = 0x0c;
    /// PrintableString.
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// IA5String.
    pub const IA5_STRING: u8 = 0x16;
    /// UTCTime.
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// SEQUENCE (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// SET (constructed).
    pub const SET: u8 = 0x31;

    /// Context-specific constructed tag `[n]`.
    pub const fn context(n: u8) -> u8 {
        0xa0 | (n & 0x1f)
    }
}

/// A DER or PEM decoding error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input ended inside a value.
    Truncated,
    /// A different tag than the structure requires.
    UnexpectedTag {
        /// The tag the structure requires.
        expected: u8,
        /// The tag found.
        found: u8,
    },
    /// Indefinite, non-minimal or oversized length.
    InvalidLength,
    /// A value that violates its type's encoding rules.
    Malformed,
    /// Bytes left over after a complete value.
    TrailingData,
    /// Bad PEM framing or base64.
    Pem,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => f.write_str("unexpected end of DER input"),
            Error::UnexpectedTag { expected, found } => {
                write!(
                    f,
                    "unexpected DER tag {found:#04x} (expected {expected:#04x})"
                )
            }
            Error::InvalidLength => f.write_str("invalid DER length encoding"),
            Error::Malformed => f.write_str("malformed DER value"),
            Error::TrailingData => f.write_str("trailing data after DER value"),
            Error::Pem => f.write_str("malformed PEM document"),
        }
    }
}

/// A cursor over DER bytes.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Start reading `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    /// Nothing left to read?
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The unread bytes.
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// One identifier octet. The high-tag-number form (low five bits all
    /// set) is rejected: no structure here uses tag numbers of 31 or more,
    /// and a single-byte tag model would misplace the element boundary.
    fn read_tag(&mut self) -> Result<u8, Error> {
        let t = self.byte()?;
        if t & 0x1f == 0x1f {
            return Err(Error::Malformed);
        }
        Ok(t)
    }

    /// A definite, minimally encoded length (X.690 §10.1).
    fn read_length(&mut self) -> Result<usize, Error> {
        let first = self.byte()?;
        if first < 0x80 {
            return Ok(usize::from(first));
        }
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(Error::InvalidLength);
        }
        let mut len: usize = 0;
        for i in 0..count {
            let b = self.byte()?;
            if i == 0 && b == 0 {
                return Err(Error::InvalidLength);
            }
            len = (len << 8) | usize::from(b);
        }
        if len < 0x80 {
            return Err(Error::InvalidLength);
        }
        Ok(len)
    }

    /// The value of the next element, which must carry `expected_tag`.
    pub fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let found = self.read_tag()?;
        if found != expected_tag {
            return Err(Error::UnexpectedTag {
                expected: expected_tag,
                found,
            });
        }
        let len = self.read_length()?;
        self.take(len)
    }

    /// A `SEQUENCE`, as a reader over its contents.
    pub fn read_sequence(&mut self) -> Result<Reader<'a>, Error> {
        Ok(Reader::new(self.read_tlv(tag::SEQUENCE)?))
    }

    /// An `INTEGER`'s raw content (two's complement, big-endian).
    pub fn read_integer_bytes(&mut self) -> Result<&'a [u8], Error> {
        self.read_tlv(tag::INTEGER)
    }

    /// A non-negative `INTEGER` in canonical DER: at least one byte, no
    /// redundant leading `0x00`, and a leading `0x00` only where the next
    /// byte's high bit would otherwise make the value negative. The returned
    /// bytes may start with that `0x00`.
    pub fn read_unsigned_integer_bytes(&mut self) -> Result<&'a [u8], Error> {
        let body = self.read_tlv(tag::INTEGER)?;
        match body {
            [] => Err(Error::Malformed),
            [0x00] => Ok(body),
            [0x00, second, ..] if second & 0x80 == 0 => Err(Error::Malformed),
            [first, ..] if *first & 0x80 != 0 => Err(Error::Malformed),
            _ => Ok(body),
        }
    }

    /// An `OCTET STRING`'s content.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], Error> {
        self.read_tlv(tag::OCTET_STRING)
    }

    /// An `OBJECT IDENTIFIER`'s encoded body.
    pub fn read_oid(&mut self) -> Result<&'a [u8], Error> {
        self.read_tlv(tag::OID)
    }

    /// A `NULL`.
    pub fn read_null(&mut self) -> Result<(), Error> {
        if self.read_tlv(tag::NULL)?.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// A `BIT STRING` with no unused bits, as its bytes.
    pub fn read_bit_string(&mut self) -> Result<&'a [u8], Error> {
        match self.read_tlv(tag::BIT_STRING)?.split_first() {
            Some((0, rest)) => Ok(rest),
            _ => Err(Error::Malformed),
        }
    }

    /// A `BOOLEAN`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        match self.read_tlv(tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(Error::Malformed),
        }
    }

    /// The next element's tag without consuming it, `None` at the end.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next element of any tag, as `(tag, value)`.
    pub fn read_any(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let t = self.read_tag()?;
        let len = self.read_length()?;
        Ok((t, self.take(len)?))
    }

    /// The next element's complete encoding, tag and length included.
    pub fn read_element(&mut self) -> Result<&'a [u8], Error> {
        let start = self.data;
        self.read_tag()?;
        let len = self.read_length()?;
        let header = start.len() - self.data.len();
        self.take(len)?;
        Ok(&start[..header + len])
    }

    /// Succeeds only if everything has been consumed.
    pub fn finish(self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }
}

// ---------------------------------------------------------------------------
// Writer

fn push_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

/// A tag-length-value element.
pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    push_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// A `SEQUENCE` around already encoded elements.
pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::SEQUENCE, content)
}

/// A non-negative `INTEGER` from a big-endian magnitude (leading zeros are
/// dropped and a sign byte added when the high bit is set).
pub fn encode_integer(unsigned_be: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < unsigned_be.len() && unsigned_be[start] == 0 {
        start += 1;
    }
    let trimmed = &unsigned_be[start..];
    if trimmed.is_empty() {
        return encode_tlv(tag::INTEGER, &[0]);
    }
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    encode_tlv(tag::INTEGER, &content)
}

/// An `OCTET STRING`.
pub fn encode_octet_string(content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::OCTET_STRING, content)
}

/// A `BIT STRING` with no unused bits.
pub fn encode_bit_string(bits: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bits.len() + 1);
    content.push(0);
    content.extend_from_slice(bits);
    encode_tlv(tag::BIT_STRING, &content)
}

/// An `OBJECT IDENTIFIER` from its encoded body.
pub fn encode_oid(body: &[u8]) -> Vec<u8> {
    encode_tlv(tag::OID, body)
}

/// A `NULL`.
pub fn encode_null() -> Vec<u8> {
    encode_tlv(tag::NULL, &[])
}

/// A `BOOLEAN`.
pub fn encode_boolean(value: bool) -> Vec<u8> {
    encode_tlv(tag::BOOLEAN, &[if value { 0xff } else { 0x00 }])
}

/// A string type (`UTF8String`, `PrintableString`, ...) with the given tag.
pub fn encode_string(tag: u8, s: &str) -> Vec<u8> {
    encode_tlv(tag, s.as_bytes())
}

/// A context-specific constructed element `[n]`.
pub fn encode_context(n: u8, content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::context(n), content)
}

// ---------------------------------------------------------------------------
// OIDs

/// The encoded body of an OID given as arcs (`[1, 2, 840, ...]`).
pub fn encode_oid_arcs(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    if arcs.len() < 2 {
        return out;
    }
    let mut push = |mut v: u64| {
        let mut tmp = [0u8; 10];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        for (k, b) in tmp[i..].iter().enumerate() {
            out.push(if k + 1 < tmp.len() - i { b | 0x80 } else { *b });
        }
    };
    push(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        push(a);
    }
    out
}

/// A complete `OBJECT IDENTIFIER` element from arcs.
pub fn oid_tlv(arcs: &[u64]) -> Vec<u8> {
    encode_oid(&encode_oid_arcs(arcs))
}

/// The arcs of an encoded OID body.
pub fn parse_oid(body: &[u8]) -> Result<Vec<u64>, Error> {
    if body.is_empty() || body[body.len() - 1] & 0x80 != 0 {
        return Err(Error::Malformed);
    }
    let mut arcs = Vec::new();
    let mut acc: u64 = 0;
    let mut first = true;
    let mut continuing = false;
    for &b in body {
        if !continuing && b == 0x80 {
            return Err(Error::Malformed); // non-minimal sub-identifier
        }
        if acc >> 57 != 0 {
            return Err(Error::Malformed); // would overflow u64
        }
        acc = (acc << 7) | u64::from(b & 0x7f);
        continuing = b & 0x80 != 0;
        if !continuing {
            if first {
                let (a0, a1) = if acc < 40 {
                    (0, acc)
                } else if acc < 80 {
                    (1, acc - 40)
                } else {
                    (2, acc - 80)
                };
                arcs.push(a0);
                arcs.push(a1);
                first = false;
            } else {
                arcs.push(acc);
            }
            acc = 0;
        }
    }
    Ok(arcs)
}

/// Dotted-decimal text of an encoded OID body.
pub fn oid_to_string(body: &[u8]) -> Result<String, Error> {
    use core::fmt::Write;
    let arcs = parse_oid(body)?;
    let mut s = String::new();
    for (i, a) in arcs.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        write!(s, "{a}").expect("writing to a String cannot fail");
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Base64 and PEM

/// Standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    base64ct::Base64::encode_string(data)
}

/// Decode standard padded base64, ignoring ASCII whitespace.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, Error> {
    let compact: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = alloc::vec![0u8; compact.len() / 4 * 3 + 3];
    let n = base64ct::Base64::decode(&compact, &mut out)
        .map_err(|_| Error::Pem)?
        .len();
    out.truncate(n);
    Ok(out)
}

/// Wrap `der` in `-----BEGIN label-----` / `-----END label-----` with
/// 64-column base64 lines.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 32);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// The DER inside the first `-----BEGIN expected_label-----` block. Fails
/// if the block is missing, duplicated, or its body is not base64.
pub fn pem_decode(pem: &str, expected_label: &str) -> Result<Vec<u8>, Error> {
    let begin = alloc::format!("-----BEGIN {expected_label}-----");
    let end = alloc::format!("-----END {expected_label}-----");
    let start = pem.find(&begin).ok_or(Error::Pem)? + begin.len();
    if pem[start..].contains(&begin) {
        return Err(Error::Pem);
    }
    let stop = pem[start..].find(&end).ok_or(Error::Pem)? + start;
    base64_decode(&pem[start..stop])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input), expected);
            assert_eq!(base64_decode(expected).unwrap(), input);
        }
        assert_eq!(base64_decode("Zm9v\nYmFy\n").unwrap(), b"foobar");
        assert!(base64_decode("Zm9vYmF").is_err());
        assert!(base64_decode("Zm9vYmF!").is_err());
    }

    #[test]
    fn pem_round_trip() {
        let der = encode_sequence(&[encode_integer(&[0x80]), encode_null()].concat());
        let pem = pem_encode("TEST", &der);
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert_eq!(pem_decode(&pem, "TEST").unwrap(), der);
        assert!(pem_decode(&pem, "OTHER").is_err());
        let twice = alloc::format!("{pem}{pem}");
        assert!(pem_decode(&twice, "TEST").is_err());
    }

    #[test]
    fn integers_are_canonical() {
        assert_eq!(encode_integer(&[0, 0, 0x7f]), alloc::vec![0x02, 0x01, 0x7f]);
        assert_eq!(encode_integer(&[0x80]), alloc::vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_integer(&[]), alloc::vec![0x02, 0x01, 0x00]);
        let mut r = Reader::new(&[0x02, 0x02, 0x00, 0x80]);
        assert_eq!(r.read_unsigned_integer_bytes().unwrap(), &[0x00, 0x80]);
        assert!(
            Reader::new(&[0x02, 0x02, 0x00, 0x7f])
                .read_unsigned_integer_bytes()
                .is_err()
        );
        assert!(
            Reader::new(&[0x02, 0x01, 0x80])
                .read_unsigned_integer_bytes()
                .is_err()
        );
        assert!(
            Reader::new(&[0x02, 0x00])
                .read_unsigned_integer_bytes()
                .is_err()
        );
    }

    #[test]
    fn lengths_are_strict() {
        assert!(
            Reader::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5])
                .read_octet_string()
                .is_err()
        );
        assert!(Reader::new(&[0x04, 0x80]).read_octet_string().is_err());
        assert!(
            Reader::new(&[0x04, 0x82, 0x00, 0x80])
                .read_octet_string()
                .is_err()
        );
        let long = alloc::vec![7u8; 200];
        let enc = encode_octet_string(&long);
        assert_eq!(&enc[..3], &[0x04, 0x81, 200]);
        let mut r = Reader::new(&enc);
        assert_eq!(r.read_octet_string().unwrap(), &long[..]);
        r.finish().unwrap();
        assert!(Reader::new(&[0x1f, 0x01, 0x00]).read_any().is_err());
    }

    #[test]
    fn elements_and_peeking() {
        let inner = [encode_boolean(true), encode_integer(&[5])].concat();
        let seq = encode_sequence(&inner);
        let mut r = Reader::new(&seq);
        assert_eq!(r.peek_tag(), Some(tag::SEQUENCE));
        let whole = r.clone().read_element().unwrap();
        assert_eq!(whole, &seq[..]);
        let mut s = r.read_sequence().unwrap();
        assert!(s.read_boolean().unwrap());
        let (t, v) = s.read_any().unwrap();
        assert_eq!((t, v), (tag::INTEGER, &[5u8][..]));
        assert!(s.is_empty());
        assert_eq!(
            Reader::new(&[0x30, 0x00, 0xff]).finish(),
            Err(Error::TrailingData)
        );
    }

    #[test]
    fn oids() {
        let body = encode_oid_arcs(&[1, 2, 840, 113549, 1, 1, 1]);
        assert_eq!(
            body,
            alloc::vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        );
        assert_eq!(oid_to_string(&body).unwrap(), "1.2.840.113549.1.1.1");
        assert_eq!(
            parse_oid(&encode_oid_arcs(&[2, 16, 840])).unwrap(),
            alloc::vec![2, 16, 840]
        );
        assert_eq!(
            oid_tlv(&[1, 3, 101, 112]),
            alloc::vec![0x06, 0x03, 0x2b, 0x65, 0x70]
        );
        assert!(parse_oid(&[0x80, 0x01]).is_err());
        assert!(parse_oid(&[0x2a, 0x86]).is_err());
        assert!(parse_oid(&[]).is_err());
    }
}
