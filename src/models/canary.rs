use super::key::Key;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Canary {
    pub key: Key,  // a canary key and nonce
    pub layer: u8, // the order in which the primary key was encrypted
}

impl Canary {
    pub fn new(key: Key, layer: u8) -> Self {
        Canary {
            key: key,
            layer: layer,
        }
    }
}
