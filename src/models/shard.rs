use super::{fragment::Fragment, key::Key, part::Part};
use serde::{Deserialize, Serialize};

/// The parts of a shard that let its trustee participate in decryption.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Secrets {
    pub key: Key,                 // this user's key for fragments in other shards
    pub fragments: Vec<Fragment>, // possible permutations of quorum
}

/// How a shard's secrets are stored on disk.
#[derive(Serialize, Deserialize, Debug)]
pub enum SecretStore {
    /// As-is: whoever holds the file holds the whole share.
    Plain(Secrets),
    /// Sealed under an Argon2id key derived from a recovery code that the
    /// creator delivers separately from the file. Without the code, the file
    /// contributes nothing but its (already encrypted) ciphertext parts.
    Locked {
        blob: Vec<u8>, // bincode of Secrets, AES-256-GCM-SIV under the derived key
        salt: Vec<u8>, // per-shard Argon2id salt
        m_cost: u32,   // Argon2id memory cost, KiB
        t_cost: u32,   // Argon2id passes
        p_cost: u32,   // Argon2id lanes
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Shard {
    pub secrets: SecretStore, // the trustee's key and fragments, maybe locked
    pub owner: u8,            // this user's ordinal
    pub pri_nonce: Vec<u8>,   // this is the nonce for the primary key
    pub parts: Vec<Part>,     // the pieces of the ciphertext this trustee holds
    pub part_count: u8,       // how many pieces the ciphertext was split into
    pub quorum: u8,           // stored here so `info` can report it even when locked
}
