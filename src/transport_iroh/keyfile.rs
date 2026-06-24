//! Encrypted-at-rest identity key — the `koh-key-v1` format.
//!
//! koh's identity key is the node's whole cryptographic identity. By default it is stored as bare
//! lowercase hex (0600), so anyone who can read the file owns the identity. This module adds an
//! OPT-IN, passphrase-encrypted format so the key is also protected by something the holder *knows*,
//! not just filesystem permissions — closing the audit-flagged plaintext-on-disk gap.
//!
//! ## Modeled on OpenSSH's `openssh-key-v1`
//!
//! The design copies OpenSSH's private-key *field discipline* (see PROTOCOL.key / `sshkey.c`): a
//! fixed magic, a named KDF whose work factor + salt are stored IN the file (so retuning never breaks
//! old files, exactly as OpenSSH stores the bcrypt round count), a named cipher, and an opaque
//! encrypted secret blob — wrapped in a text header (`koh-key-v1`) over base64, the way OpenSSH wraps
//! its binary blob in a `-----BEGIN OPENSSH PRIVATE KEY-----` PEM envelope so the file stays
//! greppable/copy-pasteable. The deliberate deviation: we use an **AEAD** (AES-256-GCM), so the
//! 16-byte tag *is* the wrong-passphrase + tamper detector — OpenSSH's two check-ints exist only
//! because its `aes256-ctr` is unauthenticated; an AEAD makes them unnecessary.
//!
//! The KDF is Argon2id with the same parameters koh already uses for the PAKE
//! ([`crate::transport_iroh::auth`]) — but here the salt is RANDOM per key (this *is* password
//! storage, unlike the PAKE's intentionally-fixed salt). No home-grown crypto: AES-GCM (RustCrypto)
//! + Argon2id, used through their safe, `Result`-returning APIs.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

/// Text header identifying an encrypted key file (the sniff anchor + greppable marker).
const HEADER: &str = "koh-key-v1";

const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_AES256GCM: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Bytes of the payload header that precede the ciphertext (and serve as the AEAD AAD):
/// version(1) + kdf(1) + cipher(1) + salt(16) + m(4) + t(4) + p(4) + nonce(12).
const AAD_LEN: usize = 1 + 1 + 1 + SALT_LEN + 4 + 4 + 4 + NONCE_LEN;
const PAYLOAD_LEN: usize = AAD_LEN + SECRET_LEN + TAG_LEN;

/// Argon2id parameters for the key file, matching the PAKE KDF: 64 MiB, 3 passes, 1 lane, 32-byte
/// output. Stored in the file so a future retune still reads old files.
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
/// Defensive ceiling on a file-supplied Argon2 memory cost, so a corrupt/hostile local key file
/// can't drive an enormous allocation. Generous vs the 64 MiB default; the key file is local-trust,
/// this is belt-and-suspenders.
const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB

/// What kind of identity-key file a blob of text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyfileKind {
    /// The legacy/default format: 64 lowercase hex chars (the bare 32-byte secret).
    PlaintextHex,
    /// A `koh-key-v1` passphrase-encrypted key.
    EncryptedV1,
}

/// Errors decoding/decrypting a key file. Typed + panic-free (untrusted-shaped, though local).
#[derive(Debug, thiserror::Error)]
pub enum KeyfileError {
    #[error("malformed koh-key-v1 file")]
    BadFormat,
    #[error("unsupported koh-key-v1 version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported koh-key-v1 KDF/cipher")]
    UnsupportedAlgo,
    #[error("koh-key-v1 KDF parameters out of range")]
    BadParams,
    #[error("wrong passphrase (or the key file was tampered with)")]
    WrongPassphrase,
    #[error("key-file crypto error")]
    Crypto,
}

/// Classify a key file's text by its header (no decryption, no secret access).
pub fn sniff(text: &str) -> KeyfileKind {
    if text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .is_some_and(|first| first == HEADER)
    {
        KeyfileKind::EncryptedV1
    } else {
        KeyfileKind::PlaintextHex
    }
}

/// Derive the 32-byte AES key from a passphrase + salt + Argon2 params (params come from the file on
/// decrypt, from constants on encrypt). Wrapped in `Zeroizing` so it's wiped on drop.
fn derive_aes_key(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, KeyfileError> {
    if m_cost > MAX_M_COST_KIB {
        return Err(KeyfileError::BadParams);
    }
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|_| KeyfileError::BadParams)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|_| KeyfileError::Crypto)?;
    Ok(key)
}

/// Encrypt a 32-byte identity secret under `passphrase`, returning the `koh-key-v1` file text
/// (a header line + base64 payload). Fresh random salt + nonce per call.
pub fn encrypt_key(secret: &[u8; 32], passphrase: &str) -> Result<String, KeyfileError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let aes_key = derive_aes_key(passphrase, &salt, M_COST_KIB, T_COST, P_COST)?;

    // The payload header (also the AEAD AAD), binding every parameter to the ciphertext.
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.push(VERSION);
    payload.push(KDF_ARGON2ID);
    payload.push(CIPHER_AES256GCM);
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&M_COST_KIB.to_le_bytes());
    payload.extend_from_slice(&T_COST.to_le_bytes());
    payload.extend_from_slice(&P_COST.to_le_bytes());
    payload.extend_from_slice(&nonce);

    let cipher = Aes256Gcm::new_from_slice(aes_key.as_slice()).map_err(|_| KeyfileError::Crypto)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: &payload, // exactly the AAD_LEN header bytes pushed so far
            },
        )
        .map_err(|_| KeyfileError::Crypto)?;
    payload.extend_from_slice(&ct);

    Ok(format!(
        "{HEADER}\n{}\n",
        data_encoding::BASE64.encode(&payload)
    ))
}

/// Decrypt a `koh-key-v1` file's text under `passphrase`, returning the 32-byte secret (zeroized on
/// drop). A wrong passphrase or any tampering fails the AEAD tag → [`KeyfileError::WrongPassphrase`].
pub fn decrypt_key(text: &str, passphrase: &str) -> Result<Zeroizing<[u8; 32]>, KeyfileError> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    if lines.next() != Some(HEADER) {
        return Err(KeyfileError::BadFormat);
    }
    let b64: String = lines.collect();
    let payload = data_encoding::BASE64
        .decode(b64.as_bytes())
        .map_err(|_| KeyfileError::BadFormat)?;
    if payload.len() != PAYLOAD_LEN {
        return Err(KeyfileError::BadFormat);
    }

    // Fixed-offset field reads via `get` (the crate forbids indexing/slicing).
    let field = |start: usize, len: usize| {
        payload
            .get(start..start + len)
            .ok_or(KeyfileError::BadFormat)
    };
    let u8at = |i: usize| payload.get(i).copied().ok_or(KeyfileError::BadFormat);
    let u32at = |start: usize| -> Result<u32, KeyfileError> {
        let b: [u8; 4] = field(start, 4)?
            .try_into()
            .map_err(|_| KeyfileError::BadFormat)?;
        Ok(u32::from_le_bytes(b))
    };

    if u8at(0)? != VERSION {
        return Err(KeyfileError::UnsupportedVersion(u8at(0)?));
    }
    if u8at(1)? != KDF_ARGON2ID || u8at(2)? != CIPHER_AES256GCM {
        return Err(KeyfileError::UnsupportedAlgo);
    }
    let salt = field(3, SALT_LEN)?;
    let m_cost = u32at(3 + SALT_LEN)?;
    let t_cost = u32at(3 + SALT_LEN + 4)?;
    let p_cost = u32at(3 + SALT_LEN + 8)?;
    let nonce = field(3 + SALT_LEN + 12, NONCE_LEN)?;
    let aad = field(0, AAD_LEN)?;
    let ct = field(AAD_LEN, SECRET_LEN + TAG_LEN)?;

    let aes_key = derive_aes_key(passphrase, salt, m_cost, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(aes_key.as_slice()).map_err(|_| KeyfileError::Crypto)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| KeyfileError::WrongPassphrase)?,
    );
    let arr: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| KeyfileError::Crypto)?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_distinguishes_formats() {
        assert_eq!(sniff("koh-key-v1\nAAAA\n"), KeyfileKind::EncryptedV1);
        assert_eq!(sniff(&"ab".repeat(32)), KeyfileKind::PlaintextHex);
        assert_eq!(sniff("\n\nkoh-key-v1\nx"), KeyfileKind::EncryptedV1);
        assert_eq!(sniff(""), KeyfileKind::PlaintextHex);
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let secret = [7u8; 32];
        let file = encrypt_key(&secret, "correct horse battery staple").unwrap();
        assert!(file.starts_with("koh-key-v1\n"), "has the header line");
        assert_eq!(sniff(&file), KeyfileKind::EncryptedV1);
        let got = decrypt_key(&file, "correct horse battery staple").unwrap();
        assert_eq!(*got, secret);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let file = encrypt_key(&[1u8; 32], "right").unwrap();
        assert!(matches!(
            decrypt_key(&file, "wrong"),
            Err(KeyfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn tampering_with_ciphertext_or_header_is_rejected() {
        let secret = [9u8; 32];
        let file = encrypt_key(&secret, "pw").unwrap();
        // Decode, flip a ciphertext (tail) byte, re-encode -> AEAD tag must fail.
        let b64: String = file.lines().skip(1).collect();
        let mut payload = data_encoding::BASE64.decode(b64.as_bytes()).unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        let tampered_ct = format!("koh-key-v1\n{}\n", data_encoding::BASE64.encode(&payload));
        assert!(matches!(
            decrypt_key(&tampered_ct, "pw"),
            Err(KeyfileError::WrongPassphrase)
        ));
        // Flip a salt byte (AAD) -> also fails (wrong derived key + AAD mismatch).
        let mut payload2 = data_encoding::BASE64.decode(b64.as_bytes()).unwrap();
        payload2[5] ^= 0x01; // inside the salt
        let tampered_salt = format!("koh-key-v1\n{}\n", data_encoding::BASE64.encode(&payload2));
        assert!(decrypt_key(&tampered_salt, "pw").is_err());
    }

    #[test]
    fn malformed_inputs_error_without_panicking() {
        assert!(matches!(
            decrypt_key("", "pw"),
            Err(KeyfileError::BadFormat)
        ));
        assert!(matches!(
            decrypt_key("koh-key-v1\nnot-base64-!!!\n", "pw"),
            Err(KeyfileError::BadFormat)
        ));
        assert!(matches!(
            decrypt_key("koh-key-v1\nAAAA\n", "pw"),
            Err(KeyfileError::BadFormat)
        ));
        // Right length but bad version byte.
        let mut p = vec![0u8; PAYLOAD_LEN];
        p[0] = 99;
        let f = format!("koh-key-v1\n{}\n", data_encoding::BASE64.encode(&p));
        assert!(matches!(
            decrypt_key(&f, "pw"),
            Err(KeyfileError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn forward_compat_reads_params_from_file() {
        // A file written with the current cost decrypts; the params are read from the file, so the
        // decrypt path does not depend on the M/T/P constants matching at read time.
        let file = encrypt_key(&[3u8; 32], "pw").unwrap();
        let payload = data_encoding::BASE64
            .decode(file.lines().skip(1).collect::<String>().as_bytes())
            .unwrap();
        let m = u32::from_le_bytes(payload[3 + 16..3 + 16 + 4].try_into().unwrap());
        assert_eq!(m, M_COST_KIB, "the cost is recorded in the file");
        assert_eq!(*decrypt_key(&file, "pw").unwrap(), [3u8; 32]);
    }
}
