use super::{fragment::Fragment, key::Key};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Shard {
    pub fragments: Vec<Fragment>, // possible permutations of quorum
    pub key: Key,                 // this user's key for fragments in other shards
    pub owner: u8,                // this user's ordinal,
    pub pri_nonce: Vec<u8>,       // this is the nonce for the primary key
}

impl Shard {
    pub fn new(owner: u8, key: Key, pri_nonce: Vec<u8>) -> Self {
        Shard {
            fragments: Vec::new(),
            key: key,
            owner: owner,
            pri_nonce: pri_nonce,
        }
    }
}
