use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Key {
    // used for both canary and trustee keys
    pub key: Vec<u8>,   // secret key
    pub nonce: Vec<u8>, // nonce for secret key
}

impl Key {
    pub fn new(key: Vec<u8>, nonce: Vec<u8>) -> Self {
        Key {
            key: key,
            nonce: nonce,
        }
    }

    pub fn clone(&self) -> Self {
        Key {
            key: self.key.clone(),
            nonce: self.nonce.clone(),
        }
    }

    pub fn xor_keys(keys: &[Key]) -> Self {
        let mut key_result = Vec::new();
        let mut nonce_result = Vec::new();

        for key in keys {
            key_result = Self::xor_vecs(&key_result, &key.key);
            nonce_result = Self::xor_vecs(&nonce_result, &key.nonce);
        }

        Key {
            key: key_result,
            nonce: nonce_result,
        }
    }

    fn xor_vecs(vec1: &[u8], vec2: &[u8]) -> Vec<u8> {
        let max_len = vec1.len().max(vec2.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let b1 = *vec1.get(i).unwrap_or(&0);
            let b2 = *vec2.get(i).unwrap_or(&0);
            result.push(b1 ^ b2);
        }

        result
    }
}
