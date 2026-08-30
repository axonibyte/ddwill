use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Fragment {
    // one possible quorum that the owning trustee could be part of, only in
    // trustee shards; the ciphertext itself lives on the shard, not here
    pub key: Vec<u8>,    // part of the primary key, currently encrypted
    pub owners: Vec<u8>, // ordinals of the other trustees needed to decrypt this fragment
}

impl Fragment {
    pub fn new(key: Vec<u8>, owners: Vec<u8>) -> Self {
        Fragment { key, owners }
    }
}
