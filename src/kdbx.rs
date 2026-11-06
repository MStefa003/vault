//! KeePass database import (`.kdbx`, format 3.1 and 4.x).
//!
//! Supported: password-protected databases using AES-256 or ChaCha20
//! encryption, AES-KDF / Argon2d / Argon2id key derivation, gzip
//! compression and Salsa20 / ChaCha20 protected values. Key-file-protected
//! and Twofish databases are refused with a clear error.
//!
//! The database is decrypted entirely in memory (in zeroizing buffers where
//! the data passes through VaultRust's own code) and nothing derived from it
//! is written anywhere except into the encrypted vault. Every length read
//! from the file is bounds-checked and the decompressed size is capped.
//!
//! Format references: KeePass `KdbxFile.*.cs` and the KeePassXC sources.

use std::io::Read;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::encoding::base64_decode;
use crate::import_export::ImportResult;
use crate::model::{Entry, EntryKind, Field, FieldKind, HistoryItem, MAX_HISTORY};
use crate::timeutil::{now_unix, parse_iso8601};

const SIG1: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const SIG2: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];

const CIPHER_AES256: [u8; 16] = hex16("31c1f2e6bf714350be5805216afc5aff");
const CIPHER_CHACHA20: [u8; 16] = hex16("d6038a2b8b6f4cb5a524339a31dbb59a");
const CIPHER_TWOFISH: [u8; 16] = hex16("ad68f29f576f4bb9a36ad47af965346c");
const KDF_AES: [u8; 16] = hex16("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_AES_KDBX4: [u8; 16] = hex16("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2D: [u8; 16] = hex16("ef636ddf8c29444b91f7a9a403e30a0c");
const KDF_ARGON2ID: [u8; 16] = hex16("9e298b1956db4773b23dfc3ec6f0a1e6");

const INNER_SALSA20: u32 = 2;
const INNER_CHACHA20: u32 = 3;
const SALSA20_NONCE: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

/// Decompressed XML larger than this is refused (zip-bomb guard).
const MAX_XML_BYTES: u64 = 256 * 1024 * 1024;
/// Key-derivation limits, so a crafted file cannot hang or exhaust memory.
/// Much lower under the fuzzer, which would otherwise report every large
/// (but legitimate) Argon2 allocation as an out-of-memory crash.
const MAX_ARGON2_MEMORY: u64 = if cfg!(fuzzing) {
    16 * 1024 * 1024
} else {
    2 * 1024 * 1024 * 1024
};
const MAX_ARGON2_ITERATIONS: u64 = if cfg!(fuzzing) { 4 } else { 10_000 };
const MAX_ARGON2_LANES: u32 = 64;
const MAX_AES_ROUNDS: u64 = if cfg!(fuzzing) { 10_000 } else { 500_000_000 };
/// Seconds between 0001-01-01 and 1970-01-01 (KDBX 4 timestamps).
const DOTNET_EPOCH_OFFSET: i64 = 62_135_596_800;

const fn hex16(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex constant"),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    #[error("{}", crate::i18n::tr("not a KeePass database"))]
    NotKdbx,
    #[error("{}", crate::i18n::format(crate::i18n::tr("KeePass database version {0}.{1} is not supported (3.1 and 4.x are)"), &[("0", .0), ("1", .1)]))]
    Version(u16, u16),
    #[error("{}", crate::i18n::format(crate::i18n::tr("the KeePass database is damaged ({0})"), &[("0", .0)]))]
    Corrupt(&'static str),
    #[error("{}", crate::i18n::tr("wrong password for this KeePass database (databases that also need a key file can't be imported)"))]
    WrongPassword,
    #[error("{}", crate::i18n::format(crate::i18n::tr("unsupported KeePass setting: {0}"), &[("0", .0)]))]
    Unsupported(&'static str),
}

type Result<T> = std::result::Result<T, KdbxError>;

/// Whether `bytes` starts with the KeePass 2.x signature.
pub fn is_kdbx(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[..4] == SIG1 && bytes[4..8] == SIG2
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or(KdbxError::Corrupt("unexpected end of data"))?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
}

fn le_u32(b: &[u8]) -> Result<u32> {
    b.try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| KdbxError::Corrupt("bad integer field"))
}

fn le_u64(b: &[u8]) -> Result<u64> {
    b.try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| KdbxError::Corrupt("bad integer field"))
}

enum Kdf {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        id: bool,
        salt: Vec<u8>,
        memory: u64,
        iterations: u64,
        lanes: u32,
        version: u32,
        secret: Option<Vec<u8>>,
    },
}

#[derive(Default)]
struct OuterHeader {
    cipher: Option<[u8; 16]>,
    compressed: bool,
    master_seed: Vec<u8>,
    iv: Vec<u8>,
    // KDBX 3.1
    transform_seed: Vec<u8>,
    transform_rounds: u64,
    protected_stream_key: Vec<u8>,
    stream_start_bytes: Vec<u8>,
    inner_stream: u32,
    // KDBX 4
    kdf: Option<Kdf>,
}

/// Decrypt and import a KeePass database.
pub fn import_kdbx(bytes: &[u8], password: &SecretString) -> Result<ImportResult> {
    if !is_kdbx(bytes) {
        return Err(KdbxError::NotKdbx);
    }
    let mut r = Reader { b: bytes, pos: 8 };
    let minor = r.u16()?;
    let major = r.u16()?;
    let kdbx4 = match (major, minor) {
        (3, 1) => false,
        (4, _) => true,
        _ => return Err(KdbxError::Version(major, minor)),
    };

    let mut h = OuterHeader::default();
    loop {
        let id = r.u8()?;
        let len = if kdbx4 {
            r.u32()? as usize
        } else {
            r.u16()? as usize
        };
        let data = r.take(len)?;
        match id {
            0 => break,
            2 => {
                h.cipher = Some(
                    data.try_into()
                        .map_err(|_| KdbxError::Corrupt("bad cipher id"))?,
                )
            }
            3 => h.compressed = le_u32(data)? == 1,
            4 => h.master_seed = data.to_vec(),
            5 => h.transform_seed = data.to_vec(),
            6 => h.transform_rounds = le_u64(data)?,
            7 => h.iv = data.to_vec(),
            8 => h.protected_stream_key = data.to_vec(),
            9 => h.stream_start_bytes = data.to_vec(),
            10 => h.inner_stream = le_u32(data)?,
            11 => h.kdf = Some(parse_kdf_parameters(data)?),
            _ => {} // comment, public custom data
        }
    }
    let header_end = r.pos;

    let composite = composite_key(password);
    let kdf = if kdbx4 {
        h.kdf
            .take()
            .ok_or(KdbxError::Corrupt("missing key derivation parameters"))?
    } else {
        Kdf::Aes {
            seed: std::mem::take(&mut h.transform_seed),
            rounds: h.transform_rounds,
        }
    };
    let transformed = transform_key(&composite, &kdf)?;
    if h.master_seed.len() != 32 {
        return Err(KdbxError::Corrupt("bad master seed"));
    }
    let master_key = sha256(&[&h.master_seed, transformed.as_slice()]);
    let cipher = h.cipher.ok_or(KdbxError::Corrupt("missing cipher id"))?;

    let (xml, inner_stream, inner_key) = if kdbx4 {
        let header_bytes = &bytes[..header_end];
        let stored_hash = r.take(32)?;
        let stored_hmac = r.take(32)?;
        if Sha256::digest(header_bytes).as_slice() != stored_hash {
            return Err(KdbxError::Corrupt("header checksum mismatch"));
        }
        let hmac_base = sha512(&[&h.master_seed, transformed.as_slice(), &[1u8]]);
        let mut mac = block_hmac(&hmac_base, u64::MAX);
        mac.update(header_bytes);
        if mac.verify_slice(stored_hmac).is_err() {
            return Err(KdbxError::WrongPassword);
        }
        let ciphertext = read_hmac_blocks(&mut r, &hmac_base)?;
        if r.pos != bytes.len() {
            return Err(KdbxError::Corrupt("data after the end of the database"));
        }
        let plain = decrypt(&cipher, &master_key, &h.iv, ciphertext)?;
        let plain = maybe_gunzip(plain, h.compressed)?;
        let mut ir = Reader { b: &plain, pos: 0 };
        let mut stream = 0;
        let mut key = Zeroizing::new(Vec::new());
        loop {
            let id = ir.u8()?;
            let len = ir.u32()? as usize;
            let data = ir.take(len)?;
            match id {
                0 => break,
                1 => stream = le_u32(data)?,
                2 => key = Zeroizing::new(data.to_vec()),
                _ => {} // attachments are not imported
            }
        }
        let xml = Zeroizing::new(ir.rest().to_vec());
        (xml, stream, key)
    } else {
        let ciphertext = r.rest();
        let plain = decrypt(&cipher, &master_key, &h.iv, ciphertext.to_vec().into())
            .map_err(|_| KdbxError::WrongPassword)?;
        if plain.len() < 32
            || h.stream_start_bytes.len() != 32
            || plain[..32] != h.stream_start_bytes[..]
        {
            return Err(KdbxError::WrongPassword);
        }
        let blocks = read_hashed_blocks(&plain[32..])?;
        let xml = maybe_gunzip(blocks, h.compressed)?;
        (
            xml,
            h.inner_stream,
            Zeroizing::new(std::mem::take(&mut h.protected_stream_key)),
        )
    };

    let mut stream = InnerStream::new(inner_stream, &inner_key)?;
    parse_xml(&xml, &mut stream)
}

fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    Zeroizing::new(h.finalize().into())
}

fn sha512(parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    Zeroizing::new(h.finalize().into())
}

fn composite_key(password: &SecretString) -> Zeroizing<[u8; 32]> {
    let pw_hash = sha256(&[password.expose_secret().as_bytes()]);
    sha256(&[pw_hash.as_slice()])
}

fn parse_kdf_parameters(data: &[u8]) -> Result<Kdf> {
    let mut r = Reader { b: data, pos: 0 };
    let version = r.u16()?;
    if version >> 8 != 1 {
        return Err(KdbxError::Unsupported("key derivation parameter format"));
    }
    let mut uuid = None;
    let mut map: Vec<(String, Vec<u8>)> = Vec::new();
    loop {
        let ty = r.u8()?;
        if ty == 0 {
            break;
        }
        let klen = usize::try_from(r.i32()?).map_err(|_| KdbxError::Corrupt("bad key length"))?;
        let key = String::from_utf8_lossy(r.take(klen)?).into_owned();
        let vlen = usize::try_from(r.i32()?).map_err(|_| KdbxError::Corrupt("bad value length"))?;
        let value = r.take(vlen)?.to_vec();
        if key == "$UUID" {
            uuid = Some(value);
        } else {
            map.push((key, value));
        }
    }
    let get = |k: &str| {
        map.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_slice())
    };
    let uuid: [u8; 16] = uuid
        .as_deref()
        .and_then(|u| u.try_into().ok())
        .ok_or(KdbxError::Corrupt("missing key derivation id"))?;
    let num = |k: &str| -> Result<u64> {
        let v = get(k).ok_or(KdbxError::Corrupt("missing key derivation parameter"))?;
        match v.len() {
            4 => Ok(u64::from(le_u32(v)?)),
            8 => le_u64(v),
            _ => Err(KdbxError::Corrupt("bad key derivation parameter")),
        }
    };
    if uuid == KDF_AES || uuid == KDF_AES_KDBX4 {
        Ok(Kdf::Aes {
            seed: get("S")
                .ok_or(KdbxError::Corrupt("missing AES-KDF seed"))?
                .to_vec(),
            rounds: num("R")?,
        })
    } else if uuid == KDF_ARGON2D || uuid == KDF_ARGON2ID {
        if get("A").is_some_and(|a| !a.is_empty()) {
            return Err(KdbxError::Unsupported("Argon2 associated data"));
        }
        Ok(Kdf::Argon2 {
            id: uuid == KDF_ARGON2ID,
            salt: get("S")
                .ok_or(KdbxError::Corrupt("missing Argon2 salt"))?
                .to_vec(),
            memory: num("M")?,
            iterations: num("I")?,
            lanes: u32::try_from(num("P")?).map_err(|_| KdbxError::Corrupt("bad Argon2 lanes"))?,
            version: u32::try_from(num("V")?)
                .map_err(|_| KdbxError::Corrupt("bad Argon2 version"))?,
            secret: get("K").filter(|k| !k.is_empty()).map(<[u8]>::to_vec),
        })
    } else {
        Err(KdbxError::Unsupported("key derivation function"))
    }
}

fn transform_key(composite: &[u8; 32], kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    match kdf {
        Kdf::Aes { seed, rounds } => {
            if seed.len() != 32 {
                return Err(KdbxError::Corrupt("bad AES-KDF seed"));
            }
            if *rounds > MAX_AES_ROUNDS {
                return Err(KdbxError::Unsupported("AES-KDF round count is too large"));
            }
            let aes = aes::Aes256::new(GenericArray::from_slice(seed));
            let mut data = Zeroizing::new(*composite);
            {
                let (a, b) = data.split_at_mut(16);
                let a = GenericArray::from_mut_slice(a);
                let b = GenericArray::from_mut_slice(b);
                for _ in 0..*rounds {
                    aes.encrypt_block(a);
                    aes.encrypt_block(b);
                }
            }
            Ok(sha256(&[data.as_slice()]))
        }
        Kdf::Argon2 {
            id,
            salt,
            memory,
            iterations,
            lanes,
            version,
            secret,
        } => {
            if *memory > MAX_ARGON2_MEMORY
                || *iterations > MAX_ARGON2_ITERATIONS
                || *lanes > MAX_ARGON2_LANES
            {
                return Err(KdbxError::Unsupported("Argon2 parameters are too large"));
            }
            let version = match version {
                0x13 => argon2::Version::V0x13,
                0x10 => argon2::Version::V0x10,
                _ => return Err(KdbxError::Unsupported("Argon2 version")),
            };
            let params = argon2::Params::new(
                (*memory / 1024) as u32,
                *iterations as u32,
                *lanes,
                Some(32),
            )
            .map_err(|_| KdbxError::Corrupt("invalid Argon2 parameters"))?;
            let alg = if *id {
                argon2::Algorithm::Argon2id
            } else {
                argon2::Algorithm::Argon2d
            };
            let argon = match secret {
                Some(k) => argon2::Argon2::new_with_secret(k, alg, version, params)
                    .map_err(|_| KdbxError::Corrupt("invalid Argon2 secret"))?,
                None => argon2::Argon2::new(alg, version, params),
            };
            let mut out = Zeroizing::new([0u8; 32]);
            argon
                .hash_password_into(composite, salt, out.as_mut_slice())
                .map_err(|_| KdbxError::Corrupt("invalid Argon2 parameters"))?;
            Ok(out)
        }
    }
}

fn block_hmac(base: &[u8; 64], index: u64) -> Hmac<Sha256> {
    let key = sha512(&[&index.to_le_bytes(), base]);
    <Hmac<Sha256> as Mac>::new_from_slice(key.as_slice()).expect("HMAC accepts any key length")
}

/// KDBX 4 payload: `[hmac 32][len i32][data]` blocks, ending with len 0.
fn read_hmac_blocks(r: &mut Reader<'_>, base: &[u8; 64]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    for index in 0u64.. {
        let tag = r.take(32)?;
        let len_raw = r.i32()?;
        let len = usize::try_from(len_raw).map_err(|_| KdbxError::Corrupt("bad block length"))?;
        let data = r.take(len)?;
        let mut mac = block_hmac(base, index);
        mac.update(&index.to_le_bytes());
        mac.update(&len_raw.to_le_bytes());
        mac.update(data);
        if mac.verify_slice(tag).is_err() {
            return Err(KdbxError::Corrupt("block authentication failed"));
        }
        if len == 0 {
            break;
        }
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// KDBX 3.1 payload: `[index u32][sha256 32][len i32][data]`, ending with len 0.
fn read_hashed_blocks(b: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut r = Reader { b, pos: 0 };
    let mut out = Zeroizing::new(Vec::new());
    for expected in 0u32.. {
        if r.u32()? != expected {
            return Err(KdbxError::Corrupt("blocks out of order"));
        }
        let hash = r.take(32)?;
        let len = usize::try_from(r.i32()?).map_err(|_| KdbxError::Corrupt("bad block length"))?;
        if len == 0 {
            // The end marker has an all-zero hash and nothing may follow it.
            if hash.iter().any(|&b| b != 0) || r.pos != r.b.len() {
                return Err(KdbxError::Corrupt("bad end of data"));
            }
            break;
        }
        let data = r.take(len)?;
        if Sha256::digest(data).as_slice() != hash {
            return Err(KdbxError::Corrupt("block checksum mismatch"));
        }
        out.extend_from_slice(data);
    }
    Ok(out)
}

fn decrypt(
    cipher: &[u8; 16],
    key: &[u8; 32],
    iv: &[u8],
    data: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if *cipher == CIPHER_AES256 {
        let dec = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| KdbxError::Corrupt("bad AES IV"))?;
        let mut buf = data;
        let n = dec
            .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|_| KdbxError::WrongPassword)?
            .len();
        buf.truncate(n);
        Ok(buf)
    } else if *cipher == CIPHER_CHACHA20 {
        let mut c = chacha20::ChaCha20::new_from_slices(key, iv)
            .map_err(|_| KdbxError::Corrupt("bad ChaCha20 nonce"))?;
        let mut buf = data;
        c.apply_keystream(&mut buf);
        Ok(buf)
    } else if *cipher == CIPHER_TWOFISH {
        Err(KdbxError::Unsupported(
            "Twofish encryption (switch the database to AES or ChaCha20 in KeePass first)",
        ))
    } else {
        Err(KdbxError::Unsupported("encryption algorithm"))
    }
}

fn maybe_gunzip(data: Zeroizing<Vec<u8>>, compressed: bool) -> Result<Zeroizing<Vec<u8>>> {
    if !compressed {
        return Ok(data);
    }
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(data.as_slice())
        .take(MAX_XML_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|_| KdbxError::Corrupt("decompression failed"))?;
    if out.len() as u64 > MAX_XML_BYTES {
        return Err(KdbxError::Unsupported(
            "the database is larger than 256 MiB",
        ));
    }
    Ok(out)
}

/// Keystream that unmasks `Protected="True"` values, in document order.
enum InnerStream {
    None,
    Salsa(salsa20::Salsa20),
    ChaCha(chacha20::ChaCha20),
}

impl InnerStream {
    fn new(id: u32, key: &[u8]) -> Result<Self> {
        Ok(match id {
            0 => InnerStream::None,
            INNER_SALSA20 => {
                let k = sha256(&[key]);
                InnerStream::Salsa(
                    salsa20::Salsa20::new_from_slices(k.as_slice(), &SALSA20_NONCE)
                        .map_err(|_| KdbxError::Corrupt("bad inner stream key"))?,
                )
            }
            INNER_CHACHA20 => {
                let h = sha512(&[key]);
                InnerStream::ChaCha(
                    chacha20::ChaCha20::new_from_slices(&h[..32], &h[32..44])
                        .map_err(|_| KdbxError::Corrupt("bad inner stream key"))?,
                )
            }
            _ => return Err(KdbxError::Unsupported("protected value cipher")),
        })
    }

    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            InnerStream::None => {}
            InnerStream::Salsa(c) => c.apply_keystream(buf),
            InnerStream::ChaCha(c) => c.apply_keystream(buf),
        }
    }
}

fn parse_xml(xml: &[u8], stream: &mut InnerStream) -> Result<ImportResult> {
    let text = std::str::from_utf8(xml).map_err(|_| KdbxError::Corrupt("XML is not UTF-8"))?;
    let opts = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: 20_000_000,
    };
    let doc = roxmltree::Document::parse_with_options(text, opts)
        .map_err(|_| KdbxError::Corrupt("XML could not be parsed"))?;

    // Unmask every protected value first: the keystream runs over them in
    // document order, including ones in history and metadata.
    let mut protected: std::collections::HashMap<roxmltree::NodeId, Zeroizing<String>> =
        Default::default();
    for node in doc.descendants().filter(|n| n.is_element()) {
        let is_protected = node
            .attribute("Protected")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if !is_protected {
            continue;
        }
        let mut raw = base64_decode(node.text().unwrap_or(""))
            .ok_or(KdbxError::Corrupt("bad protected value"))?;
        stream.apply(&mut raw);
        protected.insert(
            node.id(),
            Zeroizing::new(String::from_utf8_lossy(&raw).into_owned()),
        );
    }

    let root = doc.root_element();
    let recycle_bin = child(root, "Meta")
        .and_then(|m| child(m, "RecycleBinUUID"))
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|u| !u.is_empty() && *u != "AAAAAAAAAAAAAAAAAAAAAA==")
        .map(str::to_string);
    let top = child(root, "Root")
        .and_then(|r| child(r, "Group"))
        .ok_or(KdbxError::Corrupt("no root group"))?;

    let mut result = ImportResult {
        format: "KeePass database",
        ..Default::default()
    };
    let ctx = Ctx {
        protected: &protected,
        recycle_bin: recycle_bin.as_deref(),
    };
    walk_group(top, None, &ctx, &mut result);
    Ok(result)
}

struct Ctx<'a> {
    protected: &'a std::collections::HashMap<roxmltree::NodeId, Zeroizing<String>>,
    recycle_bin: Option<&'a str>,
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.has_tag_name(name))
}

fn walk_group(
    group: roxmltree::Node<'_, '_>,
    name: Option<&str>,
    ctx: &Ctx<'_>,
    out: &mut ImportResult,
) {
    let uuid = child(group, "UUID").and_then(|n| n.text()).map(str::trim);
    if uuid.is_some() && uuid == ctx.recycle_bin {
        return;
    }
    for c in group.children().filter(|c| c.is_element()) {
        if c.has_tag_name("Entry") {
            match convert_entry(c, name, ctx) {
                Some(e) => out.entries.push(e),
                None => out.skipped += 1,
            }
        } else if c.has_tag_name("Group") {
            let sub = child(c, "Name").and_then(|n| n.text()).unwrap_or("").trim();
            walk_group(c, (!sub.is_empty()).then_some(sub), ctx, out);
        }
    }
}

/// `Key -> (value, protected)` for an entry's `<String>` children.
fn strings(
    entry: roxmltree::Node<'_, '_>,
    ctx: &Ctx<'_>,
) -> Vec<(String, Zeroizing<String>, bool)> {
    entry
        .children()
        .filter(|c| c.has_tag_name("String"))
        .filter_map(|s| {
            let key = child(s, "Key")?.text().unwrap_or("").to_string();
            let v = child(s, "Value")?;
            match ctx.protected.get(&v.id()) {
                Some(p) => Some((key, p.clone(), true)),
                None => Some((
                    key,
                    Zeroizing::new(v.text().unwrap_or("").to_string()),
                    false,
                )),
            }
        })
        .collect()
}

fn time_of(entry: roxmltree::Node<'_, '_>, which: &str) -> Option<i64> {
    let t = child(entry, "Times")
        .and_then(|t| child(t, which))
        .and_then(|n| n.text())?
        .trim();
    if t.contains('-') {
        return parse_iso8601(t);
    }
    let raw = base64_decode(t)?;
    let secs = i64::from_le_bytes(raw.as_slice().try_into().ok()?);
    Some(secs - DOTNET_EPOCH_OFFSET)
}

fn convert_entry(
    node: roxmltree::Node<'_, '_>,
    group: Option<&str>,
    ctx: &Ctx<'_>,
) -> Option<Entry> {
    let values = strings(node, ctx);
    let get = |k: &str| {
        values
            .iter()
            .find(|(key, _, _)| key == k)
            .map(|(_, v, _)| v.as_str())
            .unwrap_or("")
    };
    let (title, user, pass, url, notes) = (
        get("Title").trim(),
        get("UserName"),
        get("Password"),
        get("URL"),
        get("Notes"),
    );
    if title.is_empty() && user.is_empty() && pass.is_empty() && url.is_empty() && notes.is_empty()
    {
        return None;
    }
    let kind = if user.is_empty() && pass.is_empty() && url.is_empty() {
        EntryKind::SecureNote
    } else {
        EntryKind::Login
    };
    let mut e = Entry::new(kind);
    e.fields.clear();
    e.title = if title.is_empty() {
        url.trim().to_string()
    } else {
        title.to_string()
    };
    if e.title.is_empty() {
        e.title = crate::i18n::tr("Imported item").into();
    }
    for (label, kind, value) in [
        ("Website", FieldKind::Url, url),
        ("Username", FieldKind::Username, user),
        ("Password", FieldKind::Password, pass),
    ] {
        if !value.is_empty() {
            e.fields.push(Field::with_value(label, kind, value));
        }
    }
    let mut has_totp = false;
    for (key, value, prot) in &values {
        if matches!(
            key.as_str(),
            "Title" | "UserName" | "Password" | "URL" | "Notes"
        ) || value.is_empty()
        {
            continue;
        }
        let field = match key.as_str() {
            "otp" | "TimeOtp-Secret-Base32" if !has_totp => {
                has_totp = true;
                Field::with_value(crate::i18n::tr("One-time code"), FieldKind::Totp, value)
            }
            k if k.starts_with("TimeOtp-") || k == "otp" => continue,
            _ => Field::with_value(
                key,
                if *prot {
                    FieldKind::Secret
                } else if value.contains('\n') {
                    FieldKind::Note
                } else {
                    FieldKind::Text
                },
                value,
            ),
        };
        e.fields.push(field);
    }
    e.notes = notes.to_string();
    if let Some(tags) = child(node, "Tags").and_then(|t| t.text()) {
        for t in tags.split([';', ',']) {
            e.add_tag(t);
        }
    }
    if let Some(g) = group {
        e.add_tag(g);
    }
    let now = now_unix();
    let plausible = |t: i64| (0..=now + 86_400).contains(&t);
    if let Some(t) = time_of(node, "CreationTime").filter(|t| plausible(*t)) {
        e.created = t;
    }
    if let Some(t) = time_of(node, "LastModificationTime").filter(|t| plausible(*t)) {
        e.modified = t;
        e.password_changed = t;
    }
    // Earlier versions of the entry become password history.
    if let Some(history) = child(node, "History") {
        let mut last: Option<String> = None;
        for old in history.children().filter(|c| c.has_tag_name("Entry")) {
            let old_strings = strings(old, ctx);
            let Some((_, pw, _)) = old_strings.iter().find(|(k, _, _)| k == "Password") else {
                continue;
            };
            if pw.is_empty() || pw.as_str() == pass || last.as_deref() == Some(pw.as_str()) {
                continue;
            }
            last = Some(pw.to_string());
            e.history.push(HistoryItem {
                label: "Password".into(),
                value: pw.to_string(),
                replaced: time_of(old, "LastModificationTime")
                    .filter(|t| plausible(*t))
                    .unwrap_or(e.modified),
            });
        }
        let excess = e.history.len().saturating_sub(MAX_HISTORY);
        e.history.drain(..excess);
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "fixture password";

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kdbx")
            .join(name);
        std::fs::read(p).unwrap()
    }

    fn check(name: &str) {
        let bytes = fixture(name);
        assert!(is_kdbx(&bytes));
        let r =
            import_kdbx(&bytes, &SecretString::from(PW)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut titles: Vec<&str> = r.entries.iter().map(|e| e.title.as_str()).collect();
        titles.sort();
        // "Old thing" is in the recycle bin and must not be imported.
        assert_eq!(
            titles,
            ["Example Mail", "Intranet", "Wi-Fi codes", "db01"],
            "{name}"
        );

        let mail = r
            .entries
            .iter()
            .find(|e| e.title == "Example Mail")
            .unwrap();
        assert_eq!(mail.kind, EntryKind::Login);
        assert_eq!(
            mail.first_of(FieldKind::Password),
            Some("current mail password")
        );
        assert_eq!(
            mail.first_of(FieldKind::Username),
            Some("alice@example.com")
        );
        assert_eq!(
            mail.first_of(FieldKind::Url),
            Some("https://mail.example.com")
        );
        assert_eq!(mail.notes, "Line one\nLine two");
        let totp = mail.totp_secret().unwrap();
        assert!(totp.starts_with("otpauth://totp/"), "{totp}");
        assert!(crate::totp::Totp::parse(totp).is_ok());
        let rec = mail
            .fields
            .iter()
            .find(|f| f.label == "Recovery code")
            .unwrap();
        assert_eq!(
            (rec.value.as_str(), rec.kind),
            ("ABCD-EFGH", FieldKind::Secret)
        );
        let acct = mail
            .fields
            .iter()
            .find(|f| f.label == "Account no")
            .unwrap();
        assert_eq!((acct.value.as_str(), acct.kind), ("12345", FieldKind::Text));
        assert!(mail.tags.iter().any(|t| t == "personal"));
        assert!(mail.tags.iter().any(|t| t == "email"));
        assert_eq!(mail.history.len(), 1, "{name}");
        assert_eq!(mail.history[0].value, "second password");
        assert!(mail.created > 1_600_000_000 && mail.created <= now_unix() + 60);

        let intranet = r.entries.iter().find(|e| e.title == "Intranet").unwrap();
        assert_eq!(
            intranet.first_of(FieldKind::Password),
            Some("intranet pw ünïcødé")
        );
        assert_eq!(intranet.tags, ["Work"]);
        let db = r.entries.iter().find(|e| e.title == "db01").unwrap();
        assert_eq!(db.tags, ["Servers"]);
        let note = r.entries.iter().find(|e| e.title == "Wi-Fi codes").unwrap();
        assert_eq!(note.kind, EntryKind::SecureNote);
        assert_eq!(note.notes, "guest: 1234");

        let wrong = import_kdbx(&bytes, &SecretString::from("not it"));
        assert!(matches!(wrong, Err(KdbxError::WrongPassword)), "{name}");
    }

    #[test]
    fn kdbx4_aes_argon2d() {
        check("kdbx4-aes-argon2d.kdbx");
    }

    #[test]
    fn kdbx4_chacha20_argon2id() {
        check("kdbx4-chacha20-argon2id.kdbx");
    }

    #[test]
    fn kdbx4_aes_kdf() {
        check("kdbx4-aes-aeskdf.kdbx");
    }

    #[test]
    fn kdbx3_aes_salsa20() {
        check("kdbx3-aes-salsa20.kdbx");
    }

    #[test]
    fn rejects_garbage_truncation_and_tampering_without_panicking() {
        let pw = SecretString::from(PW);
        assert!(matches!(import_kdbx(b"nope", &pw), Err(KdbxError::NotKdbx)));
        let good = fixture("kdbx4-aes-aeskdf.kdbx");
        // Every truncation fails cleanly.
        for len in 0..good.len() {
            assert!(import_kdbx(&good[..len], &pw).is_err(), "len {len}");
        }
        // Any flipped byte after the signature is detected.
        for i in (12..good.len()).step_by(7) {
            let mut bad = good.clone();
            bad[i] ^= 0x40;
            assert!(import_kdbx(&bad, &pw).is_err(), "byte {i}");
        }
        // KDBX 3.1 has no whole-file MAC; block hashes, the stream start
        // bytes, padding and the end marker must together catch a flip in
        // every byte of the encrypted payload.
        let v3 = fixture("kdbx3-aes-salsa20.kdbx");
        for i in 230..v3.len() {
            let mut bad = v3.clone();
            bad[i] ^= 0x01;
            assert!(import_kdbx(&bad, &pw).is_err(), "kdbx3 byte {i}");
        }
        let mut v5 = good.clone();
        v5[10] = 5;
        assert!(matches!(
            import_kdbx(&v5, &pw),
            Err(KdbxError::Version(5, _))
        ));
    }
}
