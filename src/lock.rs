//! Recovery codes: seal a shard's secrets under a key derived from a short
//! code the creator delivers separately from the shard file, so a file found
//! in the mail or a desk drawer is useless on its own.

use crate::errors::crypto_error::CryptoError;
use crate::models::shard::SecretStore;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};

/// Cost parameters for the Argon2id derivation of a recovery-code key.
#[derive(Clone, Copy, Debug)]
pub struct LockParams {
    pub m_cost: u32, // KiB
    pub t_cost: u32, // passes
    pub p_cost: u32, // lanes
}

impl Default for LockParams {
    fn default() -> Self {
        // 64 MiB, 3 passes: enough to make guessing at a 100-bit code absurd
        // and even a partially known code expensive, while a legitimate
        // decryption pays it once per shard
        LockParams {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Crockford base32: no I, L, O or U, so codes survive handwriting, phone
/// calls, and being typed back in years later.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 20; // 100 bits of entropy
const SALT_LEN: usize = 16;
const DERIVED_LEN: usize = 44; // 32-byte AES key + 12-byte nonce

/// Generate a recovery code for `owner`: `<owner>-XXXX-XXXX-XXXX-XXXX-XXXX`.
pub fn generate_code(owner: u8) -> Result<String, CryptoError> {
    let mut raw = [0u8; CODE_LEN];
    getrandom::fill(&mut raw)
        .map_err(|e| CryptoError::workflow_error(&format!("system RNG failure: {}", e)))?;
    // 256 is a multiple of 32, so `byte % 32` is uniform
    let body: Vec<u8> = raw.iter().map(|b| ALPHABET[(b % 32) as usize]).collect();
    let grouped = body
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("alphabet is ASCII"))
        .collect::<Vec<_>>()
        .join("-");
    Ok(format!("{}-{}", owner, grouped))
}

/// Parse a user-supplied code into (owner, canonical body). Forgiving about
/// case, spacing, hyphen placement, and the usual look-alikes (O->0, I/L->1).
pub fn parse_code(code: &str) -> Result<(u8, String), CryptoError> {
    let trimmed = code.trim();
    let (owner_part, body_part) = trimmed
        .split_once(['-', ' '])
        .ok_or_else(|| bad_code(trimmed))?;
    let owner: u8 = owner_part.trim().parse().map_err(|_| bad_code(trimmed))?;

    let mut body = String::with_capacity(CODE_LEN);
    for ch in body_part.chars() {
        let ch = match ch.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !ALPHABET.contains(&(ch as u8)) {
            return Err(bad_code(trimmed));
        }
        body.push(ch);
    }
    if body.len() != CODE_LEN {
        return Err(bad_code(trimmed));
    }
    Ok((owner, body))
}

fn bad_code(code: &str) -> CryptoError {
    CryptoError::workflow_error(&format!(
        "\"{}\" doesn't look like a recovery code; expected something like 3-XXXX-XXXX-XXXX-XXXX-XXXX.",
        code
    ))
}

/// Derive the AES key and nonce for a code. The owner ordinal is folded into
/// the password so a code only ever fits the shard it was printed for.
fn derive(
    owner: u8,
    body: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<([u8; 32], [u8; 12]), CryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(DERIVED_LEN))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password = format!("{}-{}", owner, body);
    let mut out = [0u8; DERIVED_LEN];
    argon.hash_password_into(password.as_bytes(), salt, &mut out)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..]);
    Ok((key, nonce))
}

/// Seal serialized shard secrets under a code.
pub fn seal(
    secrets: &[u8],
    owner: u8,
    body: &str,
    params: &LockParams,
) -> Result<SecretStore, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| CryptoError::workflow_error(&format!("system RNG failure: {}", e)))?;
    let (key, nonce) = derive(
        owner,
        body,
        &salt,
        params.m_cost,
        params.t_cost,
        params.p_cost,
    )?;
    let cipher = Aes256GcmSiv::new_from_slice(&key)?;
    let nonce = Nonce::try_from(&nonce[..]).expect("derived nonce is 12 bytes");
    let blob = cipher.encrypt(&nonce, secrets)?;
    Ok(SecretStore::Locked {
        blob,
        salt: salt.to_vec(),
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
    })
}

/// Open a locked store with a code body, yielding the serialized secrets.
pub fn open(store: &SecretStore, owner: u8, body: &str) -> Result<Vec<u8>, CryptoError> {
    match store {
        SecretStore::Locked {
            blob,
            salt,
            m_cost,
            t_cost,
            p_cost,
        } => {
            let (key, nonce) = derive(owner, body, salt, *m_cost, *t_cost, *p_cost)?;
            let cipher = Aes256GcmSiv::new_from_slice(&key)?;
            let nonce = Nonce::try_from(&nonce[..]).expect("derived nonce is 12 bytes");
            cipher.decrypt(&nonce, blob.as_slice()).map_err(|_| {
                CryptoError::workflow_error(&format!(
                    "The recovery code for shard {} is wrong (or the file is corrupted).",
                    owner
                ))
            })
        }
        SecretStore::Plain(_) => Err(CryptoError::workflow_error(
            "Tried to unlock a shard that isn't locked.",
        )),
    }
}
