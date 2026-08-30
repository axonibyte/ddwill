use super::{fragment::Fragment, key::Key, part::Part};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Shard {
    pub fragments: Vec<Fragment>, // possible permutations of quorum
    pub key: Key,                 // this user's key for fragments in other shards
    pub owner: u8,                // this user's ordinal,
    pub pri_nonce: Vec<u8>,       // this is the nonce for the primary key
    pub parts: Vec<Part>,         // the pieces of the ciphertext this trustee holds
    pub part_count: u8,           // how many pieces the ciphertext was split into
}

impl Shard {
    pub fn new(owner: u8, key: Key, pri_nonce: Vec<u8>, parts: Vec<Part>, part_count: u8) -> Self {
        Shard {
            fragments: Vec::new(),
            key,
            owner,
            pri_nonce,
            parts,
            part_count,
        }
    }
}
