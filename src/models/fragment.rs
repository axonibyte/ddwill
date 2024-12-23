use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Fragment {
    // a particular piece of the file, only in trustee shards
    pub ciphertext: Vec<u8>, // a piece of the ciphertext
    pub key: Vec<u8>,        // part of the primary key, currently encrypted
    pub owners: Vec<u8>,     // ordinals of trustees needed to decrypt this fragment
    pub nonce: Vec<u8>,      // the nonce associated with the encrypted key
}

impl Fragment {
    pub fn new(ciphertext: Vec<u8>, key: Vec<u8>, owners: Vec<u8>, nonce: Vec<u8>) -> Self {
        Fragment {
            ciphertext: ciphertext,
            key: key,
            owners: owners,
            nonce: nonce,
        }
    }
}
