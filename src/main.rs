use aes_gcm_siv:: {
    aead::{
        rand_core::RngCore,
        Aead, KeyInit, OsRng
    },
    Aes256GcmSiv, Error, Nonce
};
use clap::{
    error::ErrorKind,
    arg, command, value_parser, Command, ArgAction
};
use crypto_common::InvalidLength;
use itertools::Itertools;
use std::{
    boxed::Box,
    fmt, fs, io
};

#[derive(Debug)]
pub enum CryptoError {
    Error(Error),
    InvalidLength(InvalidLength)
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::Error(err) => write!(f, "AES error: {}", err),
            CryptoError::InvalidLength(err) => write!(f, "Invalid length error: {}", err)
        }
    }
}

impl From<Error> for CryptoError {
    fn from(err: Error) -> CryptoError {
        CryptoError::Error(err)
    }
}

impl From<InvalidLength> for CryptoError {
    fn from(err: InvalidLength) -> CryptoError {
        CryptoError::InvalidLength(err)
    }
}

#[derive(Debug)]
struct Shard { // the thing that gets sent to the trustee
    fragments: Vec<Fragment>, // possible permutations of quorum
    key: Key, // this user's key for fragments in other shards
    owner: u8, // this user's ordinal,
    pri_nonce: Vec<u8> // this is the nonce for the primary key
}

impl Shard {
    fn new(owner: u8, key: Key, pri_nonce: Vec<u8>) -> Self {
        Shard {
            fragments: Vec::new(),
            key: key,
            owner: owner,
            pri_nonce: pri_nonce
        }
    }
}

#[derive(Debug)]
struct Canary {
  key: Key, // a canary key and nonce
  layer: u8 // the order in which the primary key was encrypted
}

impl Canary {
  fn new(key: Key, layer: u8) -> Self {
    Canary {
      key: key,
      layer: layer
    }
  }
}

#[derive(Debug)]
struct Fragment { // a particular piece of the file, only in trustee shards
  ciphertext: Vec<u8>, // a piece of the ciphertext
  key: Vec<u8>, // part of the primary key, currently encrypted
  owners: Vec<u8> // ordinals of trustees needed to decrypt this fragment
}

impl Fragment {
    fn new(ciphertext: Vec<u8>, key: Vec<u8>, owners: Vec<u8>) -> Self {
        Fragment {
            ciphertext: ciphertext,
            key: key,
            owners: owners
        }
    }
}

#[derive(Debug)]
struct Key { // used for both canary and trustee keys
  key: Vec<u8>, // secret key
  nonce: Vec<u8> // nonce for secret key
}

impl Key {
    fn new(key: Vec<u8>, nonce: Vec<u8>) -> Self {
        Key {
            key: key,
            nonce: nonce
        }
    }

    fn clone(&self) -> Self {
        Key {
            key: self.key.clone(),
            nonce: self.nonce.clone()
        }
    }

    fn xor_keys(keys: &[Key]) -> Self {
        let mut key_result = Vec::new();
        let mut nonce_result = Vec::new();

        for key in keys {
            key_result = Self::xor_vecs(&key_result, &key.key);
            nonce_result = Self::xor_vecs(&nonce_result, &key.nonce);
        }

        Key {
            key: key_result,
            nonce: nonce_result
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

fn main() {
    let mut cmd = command!()
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt the payload and split it up for distribution.")
                .arg(
                    arg!(--infile <FILE>)
                        .required(true)
                        .action(ArgAction::Set))
                .arg(
                    arg!(--outdir <DIR>)
                        .required(true)
                        .action(ArgAction::Set))
                .arg(
                    arg!(--canaries <COUNT>)
                        .required(true)
                        .value_parser(value_parser!(u8))
                        .action(ArgAction::Set))
                .arg(
                    arg!(--trustees <COUNT>)
                        .required(true)
                        .value_parser(value_parser!(u8))
                        .action(ArgAction::Set))
                .arg(
                    arg!(--quorum <COUNT>)
                        .required(true)
                        .value_parser(value_parser!(u8))
                        .action(ArgAction::Set)))
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt the ciphertext and recover the will.")
                .arg(arg!(--indir <DIR>).required(true).action(ArgAction::Set)));
        let matches = cmd.get_matches_mut();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            println!(
              "'ddwill encrypt' was used",
            );

            let required_count: u8 = *sub_matches.get_one("canaries").unwrap();
            let quorum_count: u8 = *sub_matches.get_one("quorum").unwrap();
            let trustees_count: u8 = *sub_matches.get_one("trustees").unwrap();

            if quorum_count > trustees_count {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Quorum cannot be greater than number of trustees."
                )
                .exit()
            }

            let enc_res = handle_encrypt(required_count, quorum_count, trustees_count);
            match enc_res {
                Ok(()) => {
                    println!("encryption successful");
                },
                Err(e) => {
                    eprintln!("encryption failed: {}", e);
                }
            }

        },
        Some(("decrypt", _)) => {
            println!(
                "'ddwill decrypt' was used"
            );

            let dec_res = handle_decrypt();
            match dec_res {
                Ok(()) => {
                    println!("decryption successful");
                },
                Err(e) => {
                    eprintln!("decryption failed: {}", e);
                }
            }
        },
        
        _ => unreachable!("invalid subcommand")
    }
}

fn handle_encrypt(canary_count: u8, quorum_count: u8, trustees_count: u8) -> Result<(), CryptoError> {

    let pri_key = Aes256GcmSiv::generate_key(&mut OsRng);
    let pri_cipher = Aes256GcmSiv::new(&pri_key);
    let mut pri_nonce_buf = vec![0u8; 12]; // TODO this needs to be saved
    OsRng.fill_bytes(&mut pri_nonce_buf);
    let pri_nonce = Nonce::from_slice(pri_nonce_buf.as_slice());
    let mut ciphertext = pri_cipher.encrypt(pri_nonce, b"plaintext message".as_ref())?;

    let mut canaries: Vec<Canary> = Vec::new();
    for i in 0..canary_count { // encrypt ciphertext with canary keys first
      let canary_key = Aes256GcmSiv::generate_key(&mut OsRng);
      let canary_cipher = Aes256GcmSiv::new(&canary_key);
      let mut canary_nonce_buf = vec![0u8; 12];
      OsRng.fill_bytes(&mut canary_nonce_buf);
      let canary_nonce = Nonce::from_slice(canary_nonce_buf.as_slice());
      ciphertext = canary_cipher.encrypt(canary_nonce, ciphertext.as_ref()).unwrap();
      canaries.push(
          Canary::new(
              Key::new(
                  canary_key.to_vec(),
                  canary_nonce_buf
              ),
              i
          )
      );
    }

    let mut ciphertext_frags: Vec<Vec<u8>> = split_data(ciphertext, trustees_count as usize);
    let mut key_frags: Vec<Vec<u8>> = split_data(
        pri_key.as_slice().to_vec(),
        trustees_count as usize
    );

    let shards: Vec<Shard> = (0..trustees_count)
        .map(|i| {
            let mut frag_nonce = vec![0u8; 12];
            OsRng.fill_bytes(&mut frag_nonce);
            Shard::new(
                i,
                Key::new(
                    Aes256GcmSiv::generate_key(&mut OsRng).to_vec(),
                    frag_nonce
                ),
                pri_nonce_buf.clone()
            )
        })
        .collect();

    for i in 0..trustees_count { // each trustee needs their own set of fragments
        let filtered: Vec<u8> = (0..trustees_count) // get vec of all other trustees
            .filter(|&n| n != i)
            .collect();
            
        let pool: Vec<Vec<u8>> = filtered.into_iter() // get quorum combos
            .combinations((quorum_count - 1) as usize)
            .collect();
            
        for combo in &pool {
        
            // get vec of keys corresponding to each combo
            let key_set: Vec<Key> = combo.iter()
                .map(|c| shards.get(*c as usize).unwrap().key.clone())
                .collect();
            let key_combo = Key::xor_keys(&key_set); // xor each vec of keys
            
            // build cipher, nonce from xored key combo
            let shard_cipher = Aes256GcmSiv::new_from_slice(&key_combo.key)?;
            let shard_nonce = Nonce::from_slice(key_combo.nonce.as_slice());
            
            // encrypt the primary key fragment associated with outer trustee
            let enc_key_frag = shard_cipher.encrypt(
                shard_nonce,
                key_frags.get(i as usize).unwrap().as_slice()
            )?;
            let frag = Fragment::new(
                (*ciphertext_frags.get(i as usize).unwrap()).to_vec(), // frag for this trustee
                enc_key_frag,
                combo.clone()); // the combo of "other" trustees required
                
            // TODO this frag goes somewhere
        }
    }

    Ok(())
}

fn handle_decrypt() -> Result<(), CryptoError> {

    /* XXX this is for "decrypt" down below, later
    https://docs.rs/aes-gcm-siv/0.11.1/aes_gcm_siv/#usage

    let plaintext_res = cipher.decrypt(nonce, ciphertext.as_ref());
    match plaintext_res {
        Ok(plaintext) => {
            assert_eq!(&plaintext, b"plaintext message");
            eprintln!("Decryption successful.");
        },
        Err(e) => {
            eprintln!("Decryption failed: {}", e);
        }
    }
    */

    Ok(())
}

fn split_data(data: Vec<u8>, n: usize) -> Vec<Vec<u8>> {
    let len = data.len();
    let part_size = len / n; // minimum size of each part
    let remainder = len % n; // extra bytes to distribute

    let mut parts = Vec::new();
    let mut start = 0;

    for i in 0..n {
        let end = start + part_size + if i < remainder { 1 } else { 0 };
        parts.push(data[start..end].to_vec());
        start = end;
    }

    parts
}

fn reassemble_data(parts: Vec<&[u8]>) -> Vec<u8> {
    let mut result = Vec::new();

    for part in parts {
        result.extend_from_slice(part);
    }

    result
}
