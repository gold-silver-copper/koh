//! Optional FIDO2 / security-key second-factor authentication (`koh-sk-v1`).
//!
//! This is a **second pre-admission auth layer** layered *on top of* the endpoint-id allowlist, not a
//! replacement for it. iroh's QUIC/TLS handshake already authenticates the peer's node-id, and
//! `--allow <endpoint-id>` authorizes it; when the operator additionally passes `--require-sk`, the
//! server will not send the admission ack (and therefore never attaches a session, spawns a PTY, or
//! processes a single byte of terminal I/O) until the client also proves possession of an allowlisted
//! **hardware security key** — an OpenSSH `ed25519-sk` or `ecdsa-sk` FIDO2 credential.
//!
//! ## What is verified
//!
//! The client signs a fresh, connection-bound **challenge transcript** with its security key and
//! returns the OpenSSH signature blob. The transcript ([`build_transcript`]) length-prefixes and
//! binds:
//!
//! - the protocol label `koh-sk-v1`,
//! - the ALPN (`koh/iroh/1`),
//! - the SK protocol version,
//! - the **server** endpoint id,
//! - the **client** endpoint id,
//! - a fresh 32-byte server **nonce** (one per connection).
//!
//! Because the transcript is bound to the exact (server, client) pair and a per-connection nonce, a
//! signature captured on one connection cannot be replayed onto another (different nonce → different
//! transcript → the signature fails), and a signature made for a *different* server cannot be relayed
//! to koh (different server id). The server generates a new nonce for every connection and never
//! reuses one, so there is no replay window and no nonce cache to manage.
//!
//! ## The signature format
//!
//! koh verifies the exact wire format OpenSSH produces for FIDO2 keys (see `PROTOCOL.u2f` in OpenSSH),
//! so a signature from `ssh-agent`, `ssh-keygen`, or a bare token interoperates unchanged. Both
//! authenticator signatures are computed over `SHA256(application) || flags || counter ||
//! SHA256(challenge)`, and koh requires the **user-presence (touch) flag** to be set — a signature
//! with no touch is rejected. The signature checks are `ed25519-dalek`'s `verify_strict` (for
//! `sk-ssh-ed25519@openssh.com`) and `p256::ecdsa`'s `Verifier` (for
//! `sk-ecdsa-sha2-nistp256@openssh.com`) — no home-grown crypto.
//!
//! ## Scope / limitations
//!
//! - `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` are supported; other sk
//!   types (e.g. P-384/P-521) are rejected with a clear message (the dispatch point is [`SkError`]).
//! - koh cannot cryptographically *attest* that a key is genuinely hardware-backed (no FIDO attestation
//!   is exchanged): it proves possession of the private key and a user-presence assertion. Enrol only
//!   public keys you generated on real hardware. See the README threat model.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use data_encoding::{BASE64, BASE64_NOPAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// The protocol label bound into every challenge transcript (domain separation).
pub const SK_LABEL: &[u8] = b"koh-sk-v1";
/// The security-key handshake wire version (bumped if the transcript or framing changes).
pub const SK_VERSION: u8 = 1;
/// Server nonce length — a fresh one per connection.
pub const NONCE_LEN: usize = 32;

/// The single human-touch budget for a security-key handshake.
///
/// Shared so the server's admission deadline, the ssh-agent read deadline, and (with headroom) the
/// client's dial deadline stay consistent by construction rather than three independent magic numbers.
/// Generous for a real touch (typically a few seconds, plus reaching for the key / a PIN entry), yet
/// far below sshd's 120s `LoginGraceTime` — an un-keyed but allowlisted peer can only stall a pending
/// slot for this long.
pub const SK_TOUCH_GRACE: Duration = Duration::from_secs(30);

/// The OpenSSH key type for Ed25519 security keys.
const SK_ED25519_TYPE: &[u8] = b"sk-ssh-ed25519@openssh.com";
/// The OpenSSH key type for ECDSA-P256 (NIST P-256) security keys.
const SK_ECDSA_P256_TYPE: &[u8] = b"sk-ecdsa-sha2-nistp256@openssh.com";
/// The curve name embedded in an `sk-ecdsa-sha2-nistp256` public key.
const ECDSA_P256_CURVE: &[u8] = b"nistp256";
/// A SEC1 *uncompressed* P-256 point: `0x04 || X(32) || Y(32)`.
const P256_POINT_LEN: usize = 65;
/// FIDO2 authenticator-data "user present" (touch) flag. koh requires this bit to be set.
const FIDO_FLAG_USER_PRESENT: u8 = 0x01;
/// Upper bound on any single SSH-encoded field koh will parse from a peer (keys/sigs are ~100 bytes).
const MAX_SSH_STRING: usize = 4096;

/// Errors from parsing or verifying a security-key proof. Messages are deliberately non-sensitive
/// (they never echo key material) so they are safe to log and to hand to the peer as a close reason.
#[derive(Debug, thiserror::Error)]
pub enum SkError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("security-key file not found: {0}")]
    FileNotFound(String),
    #[error("security-key message was truncated")]
    Truncated,
    #[error("security-key field exceeds the maximum length")]
    FieldTooLarge,
    #[error("no security key found in the provided key/file")]
    NoKeyFound,
    #[error(
        "unsupported security-key type '{0}' (supported: sk-ssh-ed25519@openssh.com, \
         sk-ecdsa-sha2-nistp256@openssh.com)"
    )]
    UnsupportedKeyType(String),
    #[error("security-key public key has the wrong length")]
    BadKeyLength,
    #[error("security-key public key is not a valid point")]
    BadKey,
    #[error("security-key public key base64 is invalid")]
    BadBase64,
    #[error("security-key signature did not verify")]
    BadSignature,
    #[error("security-key proof lacks the user-presence (touch) flag")]
    NoUserPresence,
    #[error("presented security key is not on the allowlist")]
    KeyNotAllowed,
}

/// SHA-256 of `data` as a fixed 32-byte array (a thin, panic-free wrapper over `sha2`).
fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Render a peer-supplied algorithm name for an error/log message: lossy UTF-8 restricted to ASCII
/// graphic characters + space, and length-capped. A hostile client controls the algorithm field of
/// the blobs it sends, and that field can flow into the server's `koh::auth` audit log; without this a
/// peer could inject terminal escapes / newlines (log forging), Unicode line-separators / bidi
/// overrides (`U+2028`/`U+202E` — line splitting and Trojan-source reordering that `char::is_control`
/// does *not* catch), or ~2 KB of junk (log-volume amplification). SSH key-type names are ASCII, so
/// this loses nothing legitimate. The 64-char cap is wide enough for every real type name (the longest,
/// `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, is 43) while still bounding attacker junk.
fn sanitize_alg(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect()
}

/// Append an SSH `string` (a big-endian `u32` length prefix followed by the bytes) to `buf`.
fn push_ssh_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// A bounds-checked cursor over an SSH wire blob. Every accessor returns `Err` rather than panicking
/// on a short/oversized field, so peer-controlled bytes can never index out of range (the crate
/// forbids `indexing_slicing`).
struct SshReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SkError> {
        let end = self.pos.checked_add(n).ok_or(SkError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(SkError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, SkError> {
        self.take(1)?.first().copied().ok_or(SkError::Truncated)
    }

    fn read_u32(&mut self) -> Result<u32, SkError> {
        let arr: [u8; 4] = self.take(4)?.try_into().map_err(|_| SkError::Truncated)?;
        Ok(u32::from_be_bytes(arr))
    }

    fn string(&mut self) -> Result<&'a [u8], SkError> {
        let len = self.read_u32()? as usize;
        if len > MAX_SSH_STRING {
            return Err(SkError::FieldTooLarge);
        }
        self.take(len)
    }
}

/// The public-key material of a security key, tagged by algorithm.
#[derive(Clone, Debug)]
enum SkKeyMaterial {
    /// A raw 32-byte Ed25519 public point.
    Ed25519([u8; 32]),
    /// A SEC1 *uncompressed* P-256 public point (`0x04 || X || Y`, 65 bytes).
    EcdsaP256(Vec<u8>),
}

/// A parsed security-key signature, tagged by algorithm (the FIDO flags/counter are returned aside).
#[derive(Debug)]
enum ParsedSig {
    Ed25519([u8; 64]),
    EcdsaP256 { r: [u8; 32], s: [u8; 32] },
}

/// Encode an `sk-ssh-ed25519@openssh.com` public-key blob (the base64 body of an authorized_keys line).
fn encode_sk_ed25519_pubkey(pk: &[u8; 32], application: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    push_ssh_string(&mut b, SK_ED25519_TYPE);
    push_ssh_string(&mut b, pk);
    push_ssh_string(&mut b, application);
    b
}

/// Encode an `sk-ecdsa-sha2-nistp256@openssh.com` public-key blob.
fn encode_sk_ecdsa_pubkey(point: &[u8], application: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    push_ssh_string(&mut b, SK_ECDSA_P256_TYPE);
    push_ssh_string(&mut b, ECDSA_P256_CURVE);
    push_ssh_string(&mut b, point);
    push_ssh_string(&mut b, application);
    b
}

/// Encode an `sk-ssh-ed25519@openssh.com` signature blob (the format OpenSSH / `ssh-agent` emit).
fn encode_sk_ed25519_sig(sig: &[u8; 64], flags: u8, counter: u32) -> Vec<u8> {
    let mut b = Vec::new();
    push_ssh_string(&mut b, SK_ED25519_TYPE);
    push_ssh_string(&mut b, sig);
    b.push(flags);
    b.extend_from_slice(&counter.to_be_bytes());
    b
}

/// Encode an `sk-ecdsa-sha2-nistp256@openssh.com` signature blob (`r`/`s` as SSH mpints, then the
/// FIDO flags + counter).
fn encode_sk_ecdsa_sig(r: &[u8], s: &[u8], flags: u8, counter: u32) -> Vec<u8> {
    let mut inner = Vec::new();
    push_ssh_string(&mut inner, &encode_mpint(r));
    push_ssh_string(&mut inner, &encode_mpint(s));
    let mut b = Vec::new();
    push_ssh_string(&mut b, SK_ECDSA_P256_TYPE);
    push_ssh_string(&mut b, &inner);
    b.push(flags);
    b.extend_from_slice(&counter.to_be_bytes());
    b
}

/// The minimal SSH `mpint` body for a non-negative big-endian integer: leading zero bytes stripped,
/// with a `0x00` sign byte prepended when the high bit would otherwise be set. Zero is the empty body.
fn encode_mpint(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = bytes.get(start..).unwrap_or(&[]);
    let mut out = Vec::new();
    if let Some(&first) = trimmed.first() {
        if first & 0x80 != 0 {
            out.push(0);
        }
        out.extend_from_slice(trimmed);
    }
    out
}

/// Parse an SSH `mpint` body into a fixed 32-byte big-endian scalar (a P-256 `r`/`s`), rejecting
/// anything that doesn't fit in 32 bytes.
fn mpint_to_fixed(bytes: &[u8]) -> Result<[u8; 32], SkError> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = bytes.get(start..).unwrap_or(&[]);
    if trimmed.len() > 32 {
        return Err(SkError::BadSignature);
    }
    let mut out = [0u8; 32];
    let off = 32 - trimmed.len();
    out.get_mut(off..)
        .ok_or(SkError::BadSignature)?
        .copy_from_slice(trimmed);
    Ok(out)
}

/// Parse an OpenSSH sk signature blob (either algorithm) into `(signature, flags, counter)`.
fn parse_sk_signature(blob: &[u8]) -> Result<(ParsedSig, u8, u32), SkError> {
    let mut r = SshReader::new(blob);
    let alg = r.string()?;
    if alg == SK_ED25519_TYPE {
        let sig: [u8; 64] = r.string()?.try_into().map_err(|_| SkError::BadSignature)?;
        Ok((ParsedSig::Ed25519(sig), r.read_u8()?, r.read_u32()?))
    } else if alg == SK_ECDSA_P256_TYPE {
        // The ECDSA signature is itself an SSH blob: `string r_mpint, string s_mpint`.
        let mut inner = SshReader::new(r.string()?);
        let rr = mpint_to_fixed(inner.string()?)?;
        let ss = mpint_to_fixed(inner.string()?)?;
        Ok((
            ParsedSig::EcdsaP256 { r: rr, s: ss },
            r.read_u8()?,
            r.read_u32()?,
        ))
    } else {
        Err(SkError::UnsupportedKeyType(sanitize_alg(alg)))
    }
}

/// Verify an ECDSA-P256 signature (SHA-256) over `signed`, given the SEC1 point and `r`/`s` scalars.
fn verify_ecdsa_p256(
    point: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
    signed: &[u8],
) -> Result<(), SkError> {
    use p256::ecdsa::signature::Verifier as _;
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| SkError::BadKey)?;
    let sig = p256::ecdsa::Signature::from_scalars(*r, *s).map_err(|_| SkError::BadSignature)?;
    vk.verify(signed, &sig).map_err(|_| SkError::BadSignature)
}

/// An allowlisted (or presented) FIDO2 security-key public key (Ed25519 or ECDSA-P256).
#[derive(Clone, Debug)]
pub struct SkPublicKey {
    /// The algorithm-tagged public-key material.
    material: SkKeyMaterial,
    /// The FIDO2 application/relying-party string (`"ssh:"` for OpenSSH keys); part of the signed data.
    application: Vec<u8>,
    /// The canonical OpenSSH public-key blob — the identity used for allowlist membership + fingerprint.
    blob: Vec<u8>,
}

impl SkPublicKey {
    /// Build from an already-encoded OpenSSH public-key blob (e.g. an `ssh-agent` identity). Dispatches
    /// on the leading key-type string; both `sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256` are accepted.
    pub fn from_blob(blob: &[u8]) -> Result<Self, SkError> {
        let mut r = SshReader::new(blob);
        let alg = r.string()?;
        let material = if alg == SK_ED25519_TYPE {
            let pk: [u8; 32] = r.string()?.try_into().map_err(|_| SkError::BadKeyLength)?;
            SkKeyMaterial::Ed25519(pk)
        } else if alg == SK_ECDSA_P256_TYPE {
            let curve = r.string()?;
            if curve != ECDSA_P256_CURVE {
                return Err(SkError::UnsupportedKeyType(sanitize_alg(curve)));
            }
            let point = r.string()?;
            // OpenSSH ecdsa-sk keys carry an uncompressed SEC1 point; require exactly that shape.
            if point.len() != P256_POINT_LEN || point.first() != Some(&0x04) {
                return Err(SkError::BadKeyLength);
            }
            SkKeyMaterial::EcdsaP256(point.to_vec())
        } else {
            return Err(SkError::UnsupportedKeyType(sanitize_alg(alg)));
        };
        let application = r.string()?.to_vec();
        Ok(Self {
            material,
            application,
            blob: blob.to_vec(),
        })
    }

    /// Build an Ed25519 key from raw parts (re-deriving the canonical blob); used by the test signer.
    fn from_ed25519_parts(pk: [u8; 32], application: Vec<u8>) -> Self {
        let blob = encode_sk_ed25519_pubkey(&pk, &application);
        Self {
            material: SkKeyMaterial::Ed25519(pk),
            application,
            blob,
        }
    }

    /// Build an ECDSA-P256 key from a SEC1 point (re-deriving the canonical blob); used by the test signer.
    fn from_ecdsa_parts(point: Vec<u8>, application: Vec<u8>) -> Self {
        let blob = encode_sk_ecdsa_pubkey(&point, &application);
        Self {
            material: SkKeyMaterial::EcdsaP256(point),
            application,
            blob,
        }
    }

    /// The OpenSSH SHA256 fingerprint (`SHA256:…`), matching `ssh-keygen -lf`. Safe to log.
    pub fn fingerprint(&self) -> String {
        format!("SHA256:{}", BASE64_NOPAD.encode(&sha256(&self.blob)))
    }

    /// The canonical public-key blob (sent by the client, matched on the server).
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }
}

/// Parse the first non-comment line of an OpenSSH authorized_keys-style entry into a security key.
pub fn parse_authorized_key_line(text: &str) -> Result<SkPublicKey, SkError> {
    let content = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or(SkError::NoKeyFound)?;
    parse_one_key_line(content)
}

/// Parse EVERY non-comment/non-blank line of an OpenSSH authorized_keys-style file into a security key.
///
/// `--allow-sk <file>` naturally invites an authorized_keys-style list (one key per line), so all of
/// them must be enrolled — dropping all but the first would silently reject listed keys. A malformed
/// line is a hard error rather than being skipped: an allowlist should fail loudly (the server refuses
/// to start) instead of admitting fewer keys than the operator listed.
pub fn parse_authorized_keys(text: &str) -> Result<Vec<SkPublicKey>, SkError> {
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(parse_one_key_line(line)?);
    }
    if keys.is_empty() {
        return Err(SkError::NoKeyFound);
    }
    Ok(keys)
}

/// Parse a single OpenSSH authorized_keys-style entry (`type base64 [comment]`) into a security key.
fn parse_one_key_line(line: &str) -> Result<SkPublicKey, SkError> {
    let mut it = line.split_whitespace();
    let alg = it.next().ok_or(SkError::NoKeyFound)?;
    if alg.as_bytes() != SK_ED25519_TYPE && alg.as_bytes() != SK_ECDSA_P256_TYPE {
        return Err(SkError::UnsupportedKeyType(sanitize_alg(alg.as_bytes())));
    }
    let b64 = it.next().ok_or(SkError::NoKeyFound)?;
    let blob = BASE64
        .decode(b64.as_bytes())
        .map_err(|_| SkError::BadBase64)?;
    SkPublicKey::from_blob(&blob)
}

/// Resolve a `--allow-sk` / `--sk-key` value to every key it yields.
///
/// The value is either a path to a key file or an inline key. An existing file is read and parsed as
/// authorized_keys (every non-comment line); an inline spec yields exactly one key. A spec that fails
/// to parse inline *and* looks like a filesystem path is reported as a missing file (rather than a
/// bogus "unsupported key type").
pub fn load_sk_key_spec_all(spec: &str) -> Result<Vec<SkPublicKey>, SkError> {
    let path = Path::new(spec);
    if path.is_file() {
        let text = std::fs::read_to_string(path)?;
        return parse_authorized_keys(&text);
    }
    // Not a file — try it as an inline key line. (Base64 key bodies routinely contain `/`, so we
    // must NOT pre-classify by path characters; only fall back after an inline parse actually fails.)
    parse_authorized_key_line(spec)
        .map(|k| vec![k])
        .map_err(|e| {
            // A spec that couldn't be parsed as a key AND looks like a filesystem path is almost certainly
            // a typo'd/missing file, so report that rather than a confusing "unsupported key type <path>".
            let looks_like_path = spec.contains('/')
                || spec.starts_with('~')
                || Path::new(spec)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("pub"));
            if looks_like_path {
                SkError::FileNotFound(spec.to_string())
            } else {
                e
            }
        })
}

/// Resolve a spec to a single key (the client's `--sk-key` identity).
///
/// The client identifies with exactly one key — the first, if a file happens to list several. The
/// server allowlist path uses [`load_sk_key_spec_all`] instead, which enrolls every key in a file.
pub fn load_sk_key_spec(spec: &str) -> Result<SkPublicKey, SkError> {
    load_sk_key_spec_all(spec)?
        .into_iter()
        .next()
        .ok_or(SkError::NoKeyFound)
}

/// Build the challenge transcript that the client signs and the server re-derives.
///
/// Each field is length-prefixed so their concatenation is unambiguous (no field can bleed into the
/// next). Binds the protocol label, the ALPN, the SK version, the server id, the client id, and the
/// fresh nonce.
pub fn build_transcript(
    server_id: &[u8; 32],
    client_id: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(160);
    push_ssh_string(&mut t, SK_LABEL);
    push_ssh_string(&mut t, super::ALPN);
    push_ssh_string(&mut t, &[SK_VERSION]);
    push_ssh_string(&mut t, server_id);
    push_ssh_string(&mut t, client_id);
    push_ssh_string(&mut t, nonce);
    t
}

/// The exact bytes a FIDO2 authenticator signs: `SHA256(application) || flags || counter ||
/// SHA256(message)` (WebAuthn/CTAP `authenticatorData || clientDataHash`, as OpenSSH uses it).
fn fido_signed_data(application: &[u8], flags: u8, counter: u32, message: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(32 + 1 + 4 + 32);
    d.extend_from_slice(&sha256(application));
    d.push(flags);
    d.extend_from_slice(&counter.to_be_bytes());
    d.extend_from_slice(&sha256(message));
    d
}

/// The client's response to a challenge: the public-key blob (identity) and the signature blob.
pub struct SkResponse {
    pub pubkey_blob: Vec<u8>,
    pub signature_blob: Vec<u8>,
}

/// A successful verification — carries only the (loggable) fingerprint of the key that matched.
pub struct VerifiedSk {
    pub fingerprint: String,
}

/// The server's security-key policy: the set of allowlisted keys. Constructed from `--allow-sk`.
#[derive(Clone, Debug)]
pub struct ServerSk {
    allowed: Vec<SkPublicKey>,
}

impl ServerSk {
    /// Build directly from already-parsed keys (used by tests and any programmatic caller).
    pub fn from_keys(keys: Vec<SkPublicKey>) -> Self {
        Self { allowed: keys }
    }

    /// Parse each `--allow-sk` spec into the allowlist. A spec may be an inline key or a path to a key
    /// file; a file contributes *every* key line it holds (authorized_keys-style), so a multi-key file
    /// enrolls all of its keys rather than silently dropping all but the first. Errors if none parse.
    pub fn from_specs(specs: &[String]) -> Result<Self, SkError> {
        let mut allowed = Vec::with_capacity(specs.len());
        for s in specs {
            allowed.extend(load_sk_key_spec_all(s)?);
        }
        if allowed.is_empty() {
            return Err(SkError::NoKeyFound);
        }
        Ok(Self { allowed })
    }

    /// Number of allowlisted security keys (for the startup banner).
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Fingerprints of every allowlisted key (for the startup banner / operator confirmation).
    pub fn fingerprints(&self) -> Vec<String> {
        self.allowed.iter().map(SkPublicKey::fingerprint).collect()
    }

    /// Verify a client's response against `transcript`:
    /// 1. the presented public key must exactly match an allowlisted key,
    /// 2. the proof must carry the user-presence (touch) flag,
    /// 3. the signature must verify (Ed25519 or ECDSA-P256, matching the key's algorithm) over the
    ///    FIDO2 signed-data derived from the *trusted* allowlisted key's application (never a
    ///    peer-supplied field).
    pub fn verify(&self, transcript: &[u8], resp: &SkResponse) -> Result<VerifiedSk, SkError> {
        // Identity: the presented blob must be byte-identical to an allowlisted key. The public key
        // is not secret, so a plain comparison is fine (no timing concern).
        let matched = self
            .allowed
            .iter()
            .find(|k| k.blob == resp.pubkey_blob)
            .ok_or(SkError::KeyNotAllowed)?;

        let (parsed, flags, counter) = parse_sk_signature(&resp.signature_blob)?;
        if flags & FIDO_FLAG_USER_PRESENT == 0 {
            return Err(SkError::NoUserPresence);
        }

        // Reconstruct exactly what the authenticator signed, using the TRUSTED key's application.
        let signed = fido_signed_data(&matched.application, flags, counter, transcript);
        match (&matched.material, &parsed) {
            (SkKeyMaterial::Ed25519(pk), ParsedSig::Ed25519(sig)) => {
                let vk = VerifyingKey::from_bytes(pk).map_err(|_| SkError::BadKey)?;
                let signature = Signature::from_bytes(sig);
                vk.verify_strict(&signed, &signature)
                    .map_err(|_| SkError::BadSignature)?;
            }
            (SkKeyMaterial::EcdsaP256(point), ParsedSig::EcdsaP256 { r, s }) => {
                verify_ecdsa_p256(point, r, s, &signed)?;
            }
            // The signature's algorithm must match the enrolled key's.
            _ => return Err(SkError::BadSignature),
        }
        Ok(VerifiedSk {
            fingerprint: matched.fingerprint(),
        })
    }
}

/// A client-side signer that produces an OpenSSH security-key signature over a challenge.
///
/// The production implementation is [`AgentSkSigner`] (delegates the actual FIDO2 signing to a running
/// `ssh-agent`, which prompts for a hardware touch). [`SimAuthenticator`] is a software stand-in used
/// by the test suite. `sign` may block on hardware, so callers run it on a blocking task.
pub trait SkSigner: Send + Sync {
    /// The OpenSSH public-key blob identifying this key (sent to the server for allowlist matching).
    fn public_key_blob(&self) -> Vec<u8>;
    /// Sign the challenge `data`, returning the OpenSSH signature blob. May block (hardware touch).
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The client-side context threaded through the connector: which key to sign with and the two
/// endpoint ids the transcript binds (so a reconnect re-proves possession against a fresh nonce).
#[derive(Clone)]
pub struct ClientSkCtx {
    pub server_id: [u8; 32],
    pub client_id: [u8; 32],
    pub signer: std::sync::Arc<dyn SkSigner>,
}

/// The in-memory private key of a [`SimAuthenticator`], tagged by algorithm.
enum SimSigner {
    Ed25519(SigningKey),
    EcdsaP256(p256::ecdsa::SigningKey),
}

/// A **software** stand-in for a FIDO2 security-key authenticator (`ed25519-sk` or `ecdsa-sk`), for
/// tests and demos.
///
/// It produces byte-for-byte the same signature format a real token/`ssh-agent` emits, so the server
/// verifier cannot (and is not meant to) distinguish it — which is exactly why koh's threat model
/// states it proves key possession + a user-presence assertion, not genuine hardware backing. Do not
/// treat a `SimAuthenticator` key as a hardware second factor.
pub struct SimAuthenticator {
    signer: SimSigner,
    key: SkPublicKey,
    counter: AtomicU32,
    user_present: bool,
}

impl SimAuthenticator {
    /// Create a deterministic **ed25519-sk** authenticator from a 32-byte seed and a FIDO2 application
    /// string (`b"ssh:"` mirrors OpenSSH's default).
    pub fn new(seed: [u8; 32], application: &[u8]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let pk = signing.verifying_key().to_bytes();
        Self {
            signer: SimSigner::Ed25519(signing),
            key: SkPublicKey::from_ed25519_parts(pk, application.to_vec()),
            counter: AtomicU32::new(1),
            user_present: true,
        }
    }

    /// Create an **ecdsa-sk** (NIST P-256) authenticator with a fresh random key. (Deterministic
    /// seeding isn't offered: an arbitrary 32 bytes isn't necessarily a valid P-256 scalar, and tests
    /// only need a working key, which they enrol via [`public_key`](Self::public_key).)
    pub fn new_ecdsa(application: &[u8]) -> Self {
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signer: SimSigner::EcdsaP256(signing),
            key: SkPublicKey::from_ecdsa_parts(point, application.to_vec()),
            counter: AtomicU32::new(1),
            user_present: true,
        }
    }

    /// Simulate a token that never asserts user-presence (no touch) — used to prove koh rejects it.
    #[must_use]
    pub fn without_user_presence(mut self) -> Self {
        self.user_present = false;
        self
    }

    /// This authenticator's public key (to place on a server's `--allow-sk` list in tests).
    pub fn public_key(&self) -> SkPublicKey {
        self.key.clone()
    }
}

impl SkSigner for SimAuthenticator {
    fn public_key_blob(&self) -> Vec<u8> {
        self.key.blob.clone()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let flags = if self.user_present {
            FIDO_FLAG_USER_PRESENT
        } else {
            0
        };
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let signed = fido_signed_data(&self.key.application, flags, counter, data);
        match &self.signer {
            SimSigner::Ed25519(sk) => {
                let sig = sk
                    .try_sign(&signed)
                    .map_err(|e| anyhow::anyhow!("simulated ed25519-sk sign failed: {e}"))?;
                Ok(encode_sk_ed25519_sig(&sig.to_bytes(), flags, counter))
            }
            SimSigner::EcdsaP256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = sk
                    .try_sign(&signed)
                    .map_err(|e| anyhow::anyhow!("simulated ecdsa-sk sign failed: {e}"))?;
                let bytes = sig.to_bytes();
                let (r, s) = bytes.split_at(32);
                Ok(encode_sk_ecdsa_sig(r, s, flags, counter))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Real-hardware signer: delegate FIDO2 signing to a running ssh-agent.
//
// The agent already speaks to the token (touch prompt) and returns exactly the OpenSSH sk signature
// blob koh verifies, so koh needs no direct USB/FIDO2/libfido2 code — only a minimal agent client. Unix
// only (the agent is a unix-domain socket); off-unix, `--sk-key` errors in the CLI.
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod agent {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use anyhow::Context as _;

    use super::{SkPublicKey, SkSigner, SshReader};

    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    /// Cap on a single agent message so a hostile/broken agent can't make koh allocate unboundedly.
    const MAX_AGENT_MSG: usize = 256 * 1024;
    /// Sanity cap on the identity count in an IDENTITIES_ANSWER.
    const MAX_AGENT_IDENTITIES: u32 = 4096;
    /// Read deadline covering the human touch on a signing request (a wedged agent can't hang koh).
    /// Shares the single [`SK_TOUCH_GRACE`](super::SK_TOUCH_GRACE) budget with the server's admission
    /// deadline so the two never disagree about how long a touch may take.
    const AGENT_SIGN_TIMEOUT: Duration = super::SK_TOUCH_GRACE;
    /// Short deadline for the (non-interactive) identity listing.
    const AGENT_LIST_TIMEOUT: Duration = Duration::from_secs(5);

    /// Frame an agent payload with its big-endian `u32` length prefix.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(payload.len().saturating_add(4));
        m.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        m.extend_from_slice(payload);
        m
    }

    /// Read one length-prefixed agent message (bounded).
    fn read_message(stream: &mut UnixStream) -> anyhow::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_AGENT_MSG {
            anyhow::bail!("ssh-agent message length {len} out of range");
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn encode_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(SSH_AGENTC_SIGN_REQUEST);
        super::push_ssh_string(&mut payload, key_blob);
        super::push_ssh_string(&mut payload, data);
        payload.extend_from_slice(&flags.to_be_bytes());
        frame(&payload)
    }

    /// Extract the signature blob from a SIGN_RESPONSE (for an sk key this inner string *is* the
    /// OpenSSH sk signature blob koh verifies).
    fn parse_sign_response(msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut r = SshReader::new(msg);
        let ty = r.read_u8()?;
        if ty != SSH_AGENT_SIGN_RESPONSE {
            anyhow::bail!(
                "ssh-agent declined to sign (response type {ty}); is the security key loaded \
                 (`ssh-add`) and unlocked?"
            );
        }
        Ok(r.string()?.to_vec())
    }

    /// Parse an IDENTITIES_ANSWER into `(public-key blob, comment)` pairs.
    fn parse_identities(msg: &[u8]) -> anyhow::Result<Vec<(Vec<u8>, String)>> {
        let mut r = SshReader::new(msg);
        let ty = r.read_u8()?;
        if ty != SSH_AGENT_IDENTITIES_ANSWER {
            anyhow::bail!("unexpected ssh-agent response type {ty} to a list request");
        }
        let n = r.read_u32()?;
        if n > MAX_AGENT_IDENTITIES {
            anyhow::bail!("ssh-agent reported an implausible identity count {n}");
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let blob = r.string()?.to_vec();
            let comment = String::from_utf8_lossy(r.string()?).into_owned();
            out.push((blob, comment));
        }
        Ok(out)
    }

    /// List the agent's identities as `(blob, comment)` pairs.
    pub fn list_identities(sock: &Path) -> anyhow::Result<Vec<(Vec<u8>, String)>> {
        let mut stream = UnixStream::connect(sock)
            .with_context(|| format!("connecting to ssh-agent at {}", sock.display()))?;
        stream.set_read_timeout(Some(AGENT_LIST_TIMEOUT))?;
        stream.write_all(&frame(&[SSH_AGENTC_REQUEST_IDENTITIES]))?;
        let resp = read_message(&mut stream)?;
        parse_identities(&resp)
    }

    /// Ask the agent to sign `data` with `key_blob`, returning the OpenSSH signature blob.
    pub fn sign(sock: &Path, key_blob: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(sock)
            .with_context(|| format!("connecting to ssh-agent at {}", sock.display()))?;
        stream.set_read_timeout(Some(AGENT_SIGN_TIMEOUT))?;
        stream.write_all(&encode_sign_request(key_blob, data, 0))?;
        let resp = read_message(&mut stream)?;
        parse_sign_response(&resp)
    }

    /// Sign via a running `ssh-agent` (the production path: the agent talks to the FIDO2 token).
    pub struct AgentSkSigner {
        sock: PathBuf,
        key: SkPublicKey,
    }

    impl AgentSkSigner {
        pub fn new(sock: PathBuf, key: SkPublicKey) -> Self {
            Self { sock, key }
        }
    }

    impl SkSigner for AgentSkSigner {
        fn public_key_blob(&self) -> Vec<u8> {
            self.key.blob().to_vec()
        }

        fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
            sign(&self.sock, self.key.blob(), data)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sign_request_frames_the_key_data_and_flags() {
            let req = encode_sign_request(b"KEY", b"DATA", 0);
            // outer length prefix + payload
            let payload_len = u32::from_be_bytes([req[0], req[1], req[2], req[3]]) as usize;
            assert_eq!(payload_len, req.len() - 4);
            assert_eq!(req[4], SSH_AGENTC_SIGN_REQUEST);
            // byte(13) + string("KEY") + string("DATA") + u32(flags) = 1 + (4+3) + (4+4) + 4 = 20
            assert_eq!(payload_len, 20);
        }

        #[test]
        fn parse_sign_response_extracts_blob_and_rejects_failure() {
            // A well-formed SIGN_RESPONSE: byte(14) + string(SIGBLOB).
            let mut msg = vec![SSH_AGENT_SIGN_RESPONSE];
            super::super::push_ssh_string(&mut msg, b"SIGBLOB");
            assert_eq!(parse_sign_response(&msg).unwrap(), b"SIGBLOB");
            // SSH_AGENT_FAILURE (5) → error, not a panic.
            assert!(parse_sign_response(&[5]).is_err());
            // truncated → error.
            assert!(parse_sign_response(&[SSH_AGENT_SIGN_RESPONSE, 0, 0]).is_err());
        }

        #[test]
        fn parse_identities_reads_pairs_and_bounds_the_count() {
            let mut msg = vec![SSH_AGENT_IDENTITIES_ANSWER];
            msg.extend_from_slice(&1u32.to_be_bytes());
            super::super::push_ssh_string(&mut msg, b"BLOB");
            super::super::push_ssh_string(&mut msg, b"comment");
            let ids = parse_identities(&msg).unwrap();
            assert_eq!(ids, vec![(b"BLOB".to_vec(), "comment".to_string())]);
            // An absurd count is rejected before allocating.
            let mut bad = vec![SSH_AGENT_IDENTITIES_ANSWER];
            bad.extend_from_slice(&u32::MAX.to_be_bytes());
            assert!(parse_identities(&bad).is_err());
        }
    }
}

#[cfg(unix)]
pub use agent::{list_identities as agent_list_identities, sign as agent_sign, AgentSkSigner};

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let server_id = [7u8; 32];
        let client_id = [9u8; 32];
        let nonce = [3u8; 32];
        (server_id, client_id, nonce)
    }

    fn sim() -> SimAuthenticator {
        SimAuthenticator::new([42u8; 32], b"ssh:")
    }

    fn sim_ecdsa() -> SimAuthenticator {
        SimAuthenticator::new_ecdsa(b"ssh:")
    }

    /// The full ecdsa-sk (NIST P-256) path mirrors the ed25519 coverage: a valid, user-present proof
    /// verifies; tamper, replay, an un-allowlisted key, and a missing touch are all rejected.
    #[test]
    fn ecdsa_sk_valid_verifies_and_bad_proofs_rejected() {
        let (server_id, client_id, nonce) = ids();
        let auth = sim_ecdsa();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let transcript = build_transcript(&server_id, &client_id, &nonce);

        // The enrolled key is genuinely an ecdsa-sk key on the wire.
        assert!(auth
            .public_key_blob()
            .windows(SK_ECDSA_P256_TYPE.len())
            .any(|w| w == SK_ECDSA_P256_TYPE));

        // Valid, user-present proof verifies and reports the enrolled fingerprint.
        let good = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: auth.sign(&transcript).unwrap(),
        };
        assert_eq!(
            server.verify(&transcript, &good).unwrap().fingerprint,
            auth.public_key().fingerprint()
        );

        // A flipped signature byte is caught.
        let mut sig = auth.sign(&transcript).unwrap();
        let mid = sig.len() / 2;
        sig[mid] ^= 0xff;
        assert!(server
            .verify(
                &transcript,
                &SkResponse {
                    pubkey_blob: auth.public_key_blob(),
                    signature_blob: sig,
                },
            )
            .is_err());

        // Replay: a proof over nonce A does not verify against a fresh nonce B.
        let captured = auth
            .sign(&build_transcript(&server_id, &client_id, &[0xAA; 32]))
            .unwrap();
        let fresh = build_transcript(&server_id, &client_id, &[0xBB; 32]);
        assert!(matches!(
            server.verify(
                &fresh,
                &SkResponse {
                    pubkey_blob: auth.public_key_blob(),
                    signature_blob: captured,
                },
            ),
            Err(SkError::BadSignature)
        ));

        // A proof with no user-presence flag is rejected.
        let notouch = SimAuthenticator::new_ecdsa(b"ssh:").without_user_presence();
        let s2 = ServerSk {
            allowed: vec![notouch.public_key()],
        };
        assert!(matches!(
            s2.verify(
                &transcript,
                &SkResponse {
                    pubkey_blob: notouch.public_key_blob(),
                    signature_blob: notouch.sign(&transcript).unwrap(),
                },
            ),
            Err(SkError::NoUserPresence)
        ));

        // An ecdsa key that isn't on the allowlist is rejected.
        let attacker = sim_ecdsa();
        assert!(matches!(
            server.verify(
                &transcript,
                &SkResponse {
                    pubkey_blob: attacker.public_key_blob(),
                    signature_blob: attacker.sign(&transcript).unwrap(),
                },
            ),
            Err(SkError::KeyNotAllowed)
        ));
    }

    /// An ecdsa-sk public key round-trips through the authorized_keys text form.
    #[test]
    fn ecdsa_authorized_key_line_roundtrips() {
        let auth = sim_ecdsa();
        let blob = auth.public_key_blob();
        let line = format!(
            "sk-ecdsa-sha2-nistp256@openssh.com {} test@host",
            BASE64.encode(&blob)
        );
        let parsed = parse_authorized_key_line(&line).expect("ecdsa-sk line parses");
        assert_eq!(parsed.blob(), blob.as_slice());
        assert_eq!(parsed.fingerprint(), auth.public_key().fingerprint());
    }

    /// A signature of one algorithm cannot satisfy an enrolled key of the other (the dispatch's
    /// algorithm-mismatch arm), even though the presented public key matches the allowlist.
    #[test]
    fn algorithm_mismatch_rejected() {
        let (server_id, client_id, nonce) = ids();
        let transcript = build_transcript(&server_id, &client_id, &nonce);
        let ed = sim(); // an enrolled ed25519 key
        let server = ServerSk {
            allowed: vec![ed.public_key()],
        };
        // Present ed's (allowlisted) pubkey but an ECDSA-typed signature blob → algorithm mismatch.
        let bogus = encode_sk_ecdsa_sig(&[1u8; 32], &[2u8; 32], FIDO_FLAG_USER_PRESENT, 1);
        assert!(matches!(
            server.verify(
                &transcript,
                &SkResponse {
                    pubkey_blob: ed.public_key_blob(),
                    signature_blob: bogus,
                },
            ),
            Err(SkError::BadSignature)
        ));
    }

    /// A valid, user-present signature over the bound transcript verifies, and the fingerprint the
    /// server reports matches the enrolled key.
    #[test]
    fn valid_proof_verifies() {
        let (server_id, client_id, nonce) = ids();
        let auth = sim();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let transcript = build_transcript(&server_id, &client_id, &nonce);
        let resp = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: auth.sign(&transcript).unwrap(),
        };
        let ok = server
            .verify(&transcript, &resp)
            .expect("valid proof verifies");
        assert_eq!(ok.fingerprint, auth.public_key().fingerprint());
    }

    /// A key that is not on the allowlist is rejected — before any signature math.
    #[test]
    fn unlisted_key_rejected() {
        let (server_id, client_id, nonce) = ids();
        let enrolled = SimAuthenticator::new([1u8; 32], b"ssh:");
        let attacker = SimAuthenticator::new([2u8; 32], b"ssh:");
        let server = ServerSk {
            allowed: vec![enrolled.public_key()],
        };
        let transcript = build_transcript(&server_id, &client_id, &nonce);
        let resp = SkResponse {
            pubkey_blob: attacker.public_key_blob(),
            signature_blob: attacker.sign(&transcript).unwrap(),
        };
        assert!(matches!(
            server.verify(&transcript, &resp),
            Err(SkError::KeyNotAllowed)
        ));
    }

    /// A tampered signature does not verify.
    #[test]
    fn tampered_signature_rejected() {
        let (server_id, client_id, nonce) = ids();
        let auth = sim();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let transcript = build_transcript(&server_id, &client_id, &nonce);
        let mut sig = auth.sign(&transcript).unwrap();
        // Flip a byte inside the raw signature region (after the type string, which is 4+26 bytes,
        // then the 4-byte sig length prefix → index 34 is within the 64-byte signature).
        let idx = 34;
        sig[idx] ^= 0xff;
        let resp = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: sig,
        };
        assert!(matches!(
            server.verify(&transcript, &resp),
            Err(SkError::BadSignature)
        ));
    }

    /// A signature captured on one connection (nonce A) does not verify against a fresh challenge
    /// (nonce B): the transcript binds the nonce, so replay fails.
    #[test]
    fn replayed_signature_on_fresh_nonce_rejected() {
        let (server_id, client_id, _) = ids();
        let auth = sim();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let transcript_a = build_transcript(&server_id, &client_id, &[0xAAu8; 32]);
        let captured = auth.sign(&transcript_a).unwrap();
        // A new connection issues a different nonce.
        let transcript_b = build_transcript(&server_id, &client_id, &[0xBBu8; 32]);
        let resp = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: captured,
        };
        assert!(matches!(
            server.verify(&transcript_b, &resp),
            Err(SkError::BadSignature)
        ));
    }

    /// A signature bound to a different server id must not verify at koh (anti-relay).
    #[test]
    fn signature_for_a_different_server_rejected() {
        let (_, client_id, nonce) = ids();
        let auth = sim();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let other_server = build_transcript(&[0xEEu8; 32], &client_id, &nonce);
        let captured = auth.sign(&other_server).unwrap();
        let this_server = build_transcript(&[0x11u8; 32], &client_id, &nonce);
        let resp = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: captured,
        };
        assert!(matches!(
            server.verify(&this_server, &resp),
            Err(SkError::BadSignature)
        ));
    }

    /// A proof with no user-presence (touch) flag is rejected even if the signature is otherwise valid.
    #[test]
    fn missing_user_presence_rejected() {
        let (server_id, client_id, nonce) = ids();
        let auth = SimAuthenticator::new([5u8; 32], b"ssh:").without_user_presence();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let transcript = build_transcript(&server_id, &client_id, &nonce);
        let resp = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: auth.sign(&transcript).unwrap(),
        };
        assert!(matches!(
            server.verify(&transcript, &resp),
            Err(SkError::NoUserPresence)
        ));
    }

    /// A malformed signature blob is rejected without panicking.
    #[test]
    fn malformed_signature_blob_rejected() {
        let (server_id, client_id, nonce) = ids();
        let auth = sim();
        let server = ServerSk {
            allowed: vec![auth.public_key()],
        };
        let transcript = build_transcript(&server_id, &client_id, &nonce);
        let resp = SkResponse {
            pubkey_blob: auth.public_key_blob(),
            signature_blob: vec![0u8; 3],
        };
        assert!(server.verify(&transcript, &resp).is_err());
    }

    /// A security-key public key round-trips through the authorized_keys text form.
    #[test]
    fn authorized_key_line_roundtrips() {
        let auth = sim();
        let blob = auth.public_key_blob();
        let line = format!(
            "sk-ssh-ed25519@openssh.com {} test@host",
            BASE64.encode(&blob)
        );
        let parsed = parse_authorized_key_line(&line).expect("parses");
        assert_eq!(parsed.blob(), blob.as_slice());
        assert_eq!(parsed.fingerprint(), auth.public_key().fingerprint());
    }

    /// Comments and blank lines are skipped; the first real key line is used.
    #[test]
    fn authorized_key_line_skips_comments() {
        let auth = sim();
        let text = format!(
            "# a comment\n\nsk-ssh-ed25519@openssh.com {} k",
            BASE64.encode(&auth.public_key_blob())
        );
        assert!(parse_authorized_key_line(&text).is_ok());
    }

    /// A peer-controlled algorithm name is sanitized before it can reach the server audit log — C0
    /// controls AND Unicode line-separators / bidi overrides stripped, length actually capped — so a
    /// rejected client can't forge, reorder, or flood log lines. A *legitimate* type name is preserved.
    #[test]
    fn peer_alg_string_is_sanitized_for_logging() {
        // C0 controls (ESC, NUL, CR/LF) are stripped.
        let dirty = b"ssh-\x1b[2Jevil\ndrop\r\0table";
        assert!(
            !sanitize_alg(dirty).chars().any(char::is_control),
            "no control chars survive"
        );
        // Unicode line-separators and bidi overrides — which `char::is_control` does NOT catch — are
        // stripped too (this is the regression the earlier `is_control`-only filter allowed).
        assert_eq!(
            sanitize_alg("a\u{2028}b\u{2029}c\u{202e}d".as_bytes()),
            "abcd",
            "U+2028/U+2029/U+202E must not survive"
        );
        // The length cap actually bites: an over-long input is truncated (guards against a future
        // edit that widens/drops the cap and re-opens log-volume amplification).
        assert!(
            sanitize_alg(&vec![b'x'; 500]).chars().count() <= 64,
            "over-long input is capped"
        );
        // ...but the cap does NOT truncate a real (mis-sent) key-type name — the whole point of the
        // ecdsa-sk rejection is a message that names the offending type in full.
        assert_eq!(
            sanitize_alg(b"sk-ecdsa-sha2-nistp256@openssh.com"),
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "a legitimate 34-char type name must survive intact"
        );

        // End-to-end: a signature blob whose algorithm field is garbage-with-escapes yields an
        // UnsupportedKeyType error whose Display (what the audit log records) is control-char-free.
        let mut blob = Vec::new();
        push_ssh_string(&mut blob, b"ssh-\x1b]0;pwned\x07\nfake");
        push_ssh_string(&mut blob, &[0u8; 64]);
        blob.push(1);
        blob.extend_from_slice(&0u32.to_be_bytes());
        let err = parse_sk_signature(&blob).expect_err("bogus alg rejected");
        let msg = err.to_string();
        assert!(
            !msg.chars().any(char::is_control),
            "the logged error message must be free of control chars, got {msg:?}"
        );
    }

    /// `load_sk_key_spec` reads an existing file, parses a genuine inline key, but reports a
    /// path-shaped-yet-missing spec as a not-found file rather than a bogus "unsupported key type".
    #[test]
    fn load_sk_key_spec_distinguishes_inline_from_missing_path() {
        // A valid inline key line parses (base64 bodies can contain '/', so path chars alone must
        // never short-circuit inline parsing).
        let auth = sim();
        let line = format!(
            "sk-ssh-ed25519@openssh.com {}",
            BASE64.encode(&auth.public_key_blob())
        );
        assert!(load_sk_key_spec(&line).is_ok(), "inline key line parses");

        // Path-shaped specs that don't exist are NotFound, not a mis-parsed key type.
        for missing in [
            "/no/such/id_ed25519_sk.pub",
            "~/definitely-not-here.pub",
            "totally-missing.pub",
        ] {
            match load_sk_key_spec(missing) {
                Err(SkError::FileNotFound(p)) => assert_eq!(p, missing),
                other => panic!("expected FileNotFound for {missing}, got {other:?}"),
            }
        }

        // A non-path garbage spec still surfaces the real parse error.
        assert!(matches!(
            load_sk_key_spec("ssh-rsa AAAAsomething"),
            Err(SkError::UnsupportedKeyType(_))
        ));
    }

    /// A multi-key `--allow-sk` file (authorized_keys-style) enrolls EVERY listed key, not just the
    /// first, and a malformed line fails the whole allowlist loudly rather than silently dropping keys.
    #[test]
    fn allow_sk_file_enrolls_every_key() {
        let a = SimAuthenticator::new([10u8; 32], b"ssh:");
        let b = SimAuthenticator::new_ecdsa(b"ssh:");
        let line = |auth: &SimAuthenticator, alg: &str| {
            format!("{alg} {} admin", BASE64.encode(&auth.public_key_blob()))
        };
        let text = format!(
            "# koh security-key allowlist\n\n{}\n{}\n",
            line(&a, "sk-ssh-ed25519@openssh.com"),
            line(&b, "sk-ecdsa-sha2-nistp256@openssh.com"),
        );

        // The pure parser returns BOTH keys (comment and blank line skipped).
        let keys = parse_authorized_keys(&text).expect("both keys parse");
        assert_eq!(keys.len(), 2, "every non-comment key line is enrolled");

        // Wired through `from_specs` via a real file: both fingerprints land on the allowlist.
        let path = std::env::temp_dir().join("koh_sk_multikey_allowlist_test.pub");
        std::fs::write(&path, &text).unwrap();
        let server = ServerSk::from_specs(&[path.to_string_lossy().into_owned()]).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(server.len(), 2, "from_specs enrolls all keys in a file");
        let fps = server.fingerprints();
        assert!(fps.contains(&a.public_key().fingerprint()));
        assert!(fps.contains(&b.public_key().fingerprint()));

        // A malformed line anywhere fails the whole file (fail-closed, loudly) — no silent drop.
        let bad = format!(
            "{}\nssh-rsa AAAAnotsupported bad\n",
            line(&a, "sk-ssh-ed25519@openssh.com")
        );
        assert!(
            matches!(
                parse_authorized_keys(&bad),
                Err(SkError::UnsupportedKeyType(_))
            ),
            "a malformed line fails the whole allowlist rather than being skipped"
        );
    }

    /// An unsupported key type (e.g. P-384 ecdsa-sk, or a non-sk key) is rejected with a clear,
    /// type-naming message; the two supported sk types are accepted through to blob parsing.
    #[test]
    fn unsupported_key_type_rejected_clearly() {
        // P-384 sk keys are not supported.
        match parse_authorized_key_line("sk-ecdsa-sha2-nistp384@openssh.com AAAAstuff comment") {
            Err(SkError::UnsupportedKeyType(t)) => {
                assert!(
                    t.contains("nistp384"),
                    "message names the offending type, got {t}"
                );
            }
            other => panic!("expected UnsupportedKeyType, got {other:?}"),
        }
        // A plain (non-sk) key is rejected too.
        assert!(matches!(
            parse_authorized_key_line("ssh-ed25519 AAAAstuff c"),
            Err(SkError::UnsupportedKeyType(_))
        ));
        // The two supported sk types get PAST the type check (they fail later, on the bogus base64).
        assert!(matches!(
            parse_authorized_key_line("sk-ssh-ed25519@openssh.com !!! c"),
            Err(SkError::BadBase64)
        ));
        assert!(matches!(
            parse_authorized_key_line("sk-ecdsa-sha2-nistp256@openssh.com !!! c"),
            Err(SkError::BadBase64)
        ));
    }

    /// The transcript is sensitive to every bound field.
    #[test]
    fn transcript_binds_all_fields() {
        let base = build_transcript(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_ne!(base, build_transcript(&[9u8; 32], &[2u8; 32], &[3u8; 32]));
        assert_ne!(base, build_transcript(&[1u8; 32], &[9u8; 32], &[3u8; 32]));
        assert_ne!(base, build_transcript(&[1u8; 32], &[2u8; 32], &[9u8; 32]));
        // Starts with the domain-separation label.
        assert!(base.windows(SK_LABEL.len()).any(|w| w == SK_LABEL));
    }
}
