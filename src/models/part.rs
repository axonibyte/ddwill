use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Part {
    // one piece of the ciphertext; a shard carries every piece except a
    // window of (quorum - 1) of them, so any quorum of shards holds them all
    pub index: u8,     // position of this piece within the whole ciphertext
    pub data: Vec<u8>, // the piece itself
}

impl Part {
    pub fn new(index: u8, data: Vec<u8>) -> Self {
        Part { index, data }
    }
}
