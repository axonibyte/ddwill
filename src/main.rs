mod models;

use aes_gcm_siv::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256GcmSiv, Error, Nonce,
};
use clap::{arg, command, error::ErrorKind, value_parser, ArgAction, Command};
use crypto_common::InvalidLength;
use hex;
use itertools::Itertools;
use models::{
    canary::Canary,
    deliverable::{self, Deliverable},
    fragment::Fragment,
    key::Key,
    shard::Shard,
};
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

#[derive(Debug)]
pub enum CryptoError {
    AESError(Error),
    InvalidLength(InvalidLength),
    IOError(std::io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::AESError(err) => write!(f, "AES error: {}", err),
            CryptoError::InvalidLength(err) => write!(f, "Invalid length error: {}", err),
            CryptoError::IOError(err) => write!(f, "STD error: {}", err),
        }
    }
}

impl From<Error> for CryptoError {
    fn from(err: Error) -> CryptoError {
        CryptoError::AESError(err)
    }
}

impl From<InvalidLength> for CryptoError {
    fn from(err: InvalidLength) -> CryptoError {
        CryptoError::InvalidLength(err)
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> CryptoError {
        CryptoError::IOError(err)
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
                .arg(arg!(--infile <FILE>).required(true).action(ArgAction::Set))
                .arg(arg!(--outdir <DIR>).required(true).action(ArgAction::Set))
                .arg(
                    arg!(--canaries <COUNT>)
                        .required(true)
                        .value_parser(value_parser!(u8))
                        .action(ArgAction::Set),
                )
                .arg(
                    arg!(--trustees <COUNT>)
                        .required(true)
                        .value_parser(value_parser!(u8))
                        .action(ArgAction::Set),
                )
                .arg(
                    arg!(--quorum <COUNT>)
                        .required(true)
                        .value_parser(value_parser!(u8))
                        .action(ArgAction::Set),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt the ciphertext and recover the will.")
                .arg(arg!(--indir <DIR>).required(true).action(ArgAction::Set))
                .arg(arg!(--outfile <FILE>).required(true).action(ArgAction::Set)),
        );
    let matches = cmd.get_matches_mut();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            println!("'ddwill encrypt' was used",);

            let required_count: u8 = *sub_matches.get_one("canaries").unwrap();
            let quorum_count: u8 = *sub_matches.get_one("quorum").unwrap();
            let trustees_count: u8 = *sub_matches.get_one("trustees").unwrap();
            let input_file = Path::new(sub_matches.get_one::<String>("infile").unwrap());
            let output_dir = Path::new(sub_matches.get_one::<String>("outdir").unwrap());

            if quorum_count > trustees_count {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Quorum cannot be greater than number of trustees.",
                )
                .exit()
            }

            if !input_file.exists() {
                cmd.error(ErrorKind::ValueValidation, "Input file does not exist.")
                    .exit();
            } else if !input_file.is_file() {
                cmd.error(ErrorKind::ValueValidation, "Specified input is not a file.")
                    .exit();
            }

            if !output_dir.exists() {
                if let Err(_e) = fs::create_dir_all(output_dir) {
                    cmd.error(
                        ErrorKind::ValueValidation,
                        "Error creating output directory.",
                    )
                    .exit();
                }
            } else if !output_dir.is_dir() {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Specified output exists but is not a directory.",
                )
                .exit();
            }

            let enc_res = handle_encrypt(
                required_count,
                quorum_count,
                trustees_count,
                input_file,
                output_dir,
            );
            match enc_res {
                Ok(()) => {
                    println!("encryption successful");
                }
                Err(e) => {
                    eprintln!("encryption failed: {}", e);
                }
            }
        }
        Some(("decrypt", sub_matches)) => {
            println!("'ddwill decrypt' was used");

            let input_dir = Path::new(sub_matches.get_one::<String>("indir").unwrap());
            let output_file = Path::new(sub_matches.get_one::<String>("outfile").unwrap());

            if !input_dir.exists() {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Input directory does not exist.",
                )
                .exit();
            } else if !input_dir.is_dir() {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Specified input is not a directory.",
                )
                .exit();
            }

            if output_file.exists() && !output_file.is_file() {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Specified output exists but is not a file.",
                )
                .exit();
            }

            let dec_res = handle_decrypt(input_dir, output_file);
            match dec_res {
                Ok(()) => {
                    println!("decryption successful");
                }
                Err(e) => {
                    eprintln!("decryption failed: {}", e);
                }
            }
        }

        _ => unreachable!("invalid subcommand"),
    }
}

fn handle_encrypt(
    canary_count: u8,
    quorum_count: u8,
    trustees_count: u8,
    input_path: &Path,
    output_path: &Path,
) -> Result<(), CryptoError> {
    // generate primary cryptovariables for encryption
    let pri_key = Aes256GcmSiv::generate_key(&mut OsRng);
    let pri_cipher = Aes256GcmSiv::new(&pri_key);
    let mut pri_nonce_buf = vec![0u8; 12];
    OsRng.fill_bytes(&mut pri_nonce_buf);
    let pri_nonce = Nonce::from_slice(pri_nonce_buf.as_slice());

    // grab the plaintext to be encrypted
    let mut input_file = fs::File::open(input_path)?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;

    // encrypt the plaintext with the primary key
    let ciphertext = pri_cipher.encrypt(pri_nonce, plaintext.as_slice().as_ref())?;
    let mut pri_key_enc = pri_key.as_slice().to_vec();

    // XXX debug begin
    println!("plaintext = {}", hex::encode(plaintext.clone()));
    println!("ciphertext = {}", hex::encode(ciphertext.clone()));
    println!("pri_key = {}", hex::encode(pri_key_enc.clone()));
    println!("pri_nonce = {}", hex::encode(pri_nonce_buf.clone()));
    // XXX debug end

    let mut canaries: Vec<Canary> = Vec::new();
    for i in 0..canary_count {
        // generate a set of canary cryptovariables for encryption
        let canary_key = Aes256GcmSiv::generate_key(&mut OsRng);
        let canary_cipher = Aes256GcmSiv::new(&canary_key);
        let mut canary_nonce_buf = vec![0u8; 12];
        OsRng.fill_bytes(&mut canary_nonce_buf);
        let canary_nonce = Nonce::from_slice(canary_nonce_buf.as_slice());

        // encrypt the private key with a canary k ey
        pri_key_enc = canary_cipher
            .encrypt(canary_nonce, pri_key_enc.as_ref())
            .unwrap();

        // XXX debug begin
        println!(
            "canary {} encrypts primary key\n- pri_key = {}",
            i,
            hex::encode(pri_key_enc.clone())
        );
        // XXX debug end

        // save the canary in memory
        canaries.push(Canary::new(
            Key::new(canary_key.to_vec(), canary_nonce_buf),
            i,
        ));
    }

    // create a shard to distribute to each trustee
    let mut shards: Vec<Shard> = (0..trustees_count)
        .map(|i| {
            // each shard has a unique nonce, which will be XORed with the other
            // nonces to create a per-fragment nonce
            let mut frag_nonce = vec![0u8; 12];
            OsRng.fill_bytes(&mut frag_nonce);
            Shard::new(
                // each trustee has a unique key and a copy of the primary nonce
                i,
                Key::new(Aes256GcmSiv::generate_key(&mut OsRng).to_vec(), frag_nonce),
                pri_nonce_buf.clone(),
            )
        })
        .collect();

    for i in 0..trustees_count {
        // each trustee needs their own set of fragments
        let filtered: Vec<u8> = (0..trustees_count) // get vec of all other trustees
            .filter(|&n| n != i)
            .collect();
        let pool: Vec<Vec<u8>> = filtered
            .into_iter() // get quorum combos
            .combinations((quorum_count - 1) as usize)
            .collect();

        for combo in &pool {
            // get vec of keys corresponding to each combo
            let key_set: Vec<Key> = combo
                .iter()
                .map(|c| shards.get(*c as usize).unwrap().key.clone())
                .collect();
            let key_combo = Key::xor_keys(&key_set); // xor each vec of keys

            // XXX debug begin
            println!(
                "outer trustee {} and inner combo {:?}\n- yields key {}\n- yields nonce {}",
                i,
                combo,
                hex::encode(key_combo.key.clone()),
                hex::encode(key_combo.nonce.clone())
            );
            // XXX debug end

            // build cipher, nonce from xored key combo
            let shard_cipher = Aes256GcmSiv::new_from_slice(&key_combo.key)?;
            let shard_nonce = Nonce::from_slice(key_combo.nonce.as_slice());

            // here we need to build a fragment with certain requirements:
            // - it needs to contain pieces of the encrypted message and primary
            //   key that corresponds to the inner combo'd trustees (not the
            //   outer trustee)
            // - the key fragment needs to be encrypted with the combo key/nonce
            // - the combo'd nonce needs to be included with the fragment

            // so figure out where outer trustee would be in the pool of inner
            // trustees, if it were added (this index corresponds with the part
            // we need to remove from the ciphertext and encrypted key)
            let assumed_order = find_insert_index(combo, i);

            let frag = Fragment::new(
                // remove the part of the ciphertext that corresponds with the
                // outer trustee
                remove_part(&ciphertext, quorum_count as usize, assumed_order),
                // encrypt the remaining parts of the primary key
                shard_cipher.encrypt(
                    shard_nonce,
                    // remove the part of the primary key that corresponds with
                    // the outer trustee
                    remove_part(
                        &pri_key_enc.as_slice().to_vec(),
                        quorum_count as usize,
                        assumed_order,
                    )
                    .as_slice(),
                )?,
                combo.clone(),   // keep track of the inner trustees
                key_combo.nonce, // remember the nonce used for this XXX needed?
            );

            // XXX debug begin
            println!(
                "new frag pushed to owner {}\n- with key {}\n- with ciphertext {}\n- with nonce {}",
                i,
                hex::encode(frag.key.clone()),
                hex::encode(frag.ciphertext.clone()),
                hex::encode(frag.nonce.clone())
            );
            // XXX debug end

            // this frag gets pushed to the shard for the outer trustee
            shards[i as usize].fragments.push(frag);
        }
    }

    // serialization time!
    for canary in canaries {
        let _ = deliverable::commit_deliverable(
            output_path,
            &format!("canary_{}.will", canary.layer),
            &Deliverable::Canary(canary),
        );
    }

    for shard in shards {
        let _ = deliverable::commit_deliverable(
            output_path,
            &format!("shard_{}.will", shard.owner),
            &Deliverable::Shard(shard),
        );
    }

    Ok(())
}

fn handle_decrypt(input_path: &Path, output_path: &Path) -> Result<(), CryptoError> {
    let mut canaries: Vec<Canary> = Vec::new();
    let mut shards: Vec<Shard> = Vec::new();

    for entry in fs::read_dir(input_path)? {
        let file = entry?.path();
        if file.is_file() {
            match deliverable::retrieve_deliverable(&file) {
                Ok(Deliverable::Canary(canary)) => {
                    println!("found canary (layer {})", canary.layer);
                    canaries.push(canary);
                }
                Ok(Deliverable::Shard(shard)) => {
                    println!("found shard: (owner {})", shard.owner);
                    shards.push(shard);
                }
                Err(e) => {
                    println!("failed to deserialize {}: {}", file.display(), e);
                }
            }
        }
    }

    // all canaries and shards are loaded;
    // we need a fragment from each of the trustees;
    // remember that the user may have provided greater or fewer files than
    // strictly required

    shards.sort_by(|a, b| a.owner.cmp(&b.owner));
    let shard_owners: Vec<u8> = shards.iter().map(|shard| shard.owner).collect();
    let mut frag_owners: Vec<u8> = Vec::new();

    //let mut ciphertext_frags: Vec<Vec<u8>> = Vec::new();
    //let mut key_frags: Vec<Vec<u8>> = Vec::new();

    if let Some(first_shard) = shards.first() {
        let first_fragment = first_shard.fragments.iter().find(|fragment| {
            fragment
                .owners
                .iter()
                .all(|owner| shard_owners.contains(owner))
        });

        if let Some(fragment) = first_fragment {
            frag_owners.push(first_shard.owner);
            frag_owners.extend(fragment.owners.clone());
            //ciphertext_frags.extend(split_data(fragment.ciphertext.clone(), frag_owners.len()));
            //key_frags.extend(split_data(fragment.key.clone(), frag_owners.len()));
        } else {
            panic!("no matching fragments!");
        }
    } else {
        panic!("no shards available!");
    }

    // at this point, we have a quorum
    println!("frag owners: {:?}", frag_owners);

    // let's get all the associated fragments
    let relevant_shards: Vec<&Shard> = shards
        .iter()
        .filter(|shard| frag_owners.contains(&shard.owner))
        .collect();
    let relevant_fragments: Vec<&Fragment> = relevant_shards
        .iter()
        .flat_map(|shard| {
            shard.fragments.iter().filter(|fragment| {
                frag_owners.contains(&shard.owner)
                    && fragment
                        .owners
                        .iter()
                        .all(|owner| frag_owners.contains(owner))
            })
        })
        .collect();

    // XXX debug start
    for (idx, frag) in relevant_fragments.iter().enumerate() {
        println!(
            "fragment from owner {}\n- key: {}\n- ciphertext: {}\n- nonce: {}",
            relevant_shards[idx].owner.clone(),
            hex::encode(frag.key.clone()),
            hex::encode(frag.ciphertext.clone()),
            hex::encode(frag.nonce.clone())
        );
    }
    // XXX debug stop

    // so we need to calculate the combo key and nonce for the first two shards
    // we only need the first two because their union should constitute the
    // whole of the encrypted stuff (with some duplicates, which we'll handle)
    let mut combo_keys: Vec<Key> = Vec::new();
    for s_idx in 0..2 {
        let combo_key = Key::xor_keys(
            relevant_shards
                .iter()
                .filter(|s| s.owner != relevant_shards[s_idx].owner)
                .map(|s| s.key.clone())
                .collect::<Vec<Key>>()
                .as_slice(),
        );

        // XXX debug start
        println!(
            "reconstructed combo key:\n- key: {}\n- nonce: {}",
            hex::encode(combo_key.key.clone()),
            hex::encode(combo_key.nonce.clone())
        );
        // XXX debug end

        combo_keys.push(combo_key);
    }

    // so here, we want to reconstruct the encrypted primary key with the two
    // combo keys that we've recovered and their respective fragments
    let shard0_cipher = Aes256GcmSiv::new_from_slice(combo_keys[0].key.as_slice())?;
    let shard0_nonce = Nonce::from_slice(combo_keys[0].nonce.as_slice());
    let shard1_cipher = Aes256GcmSiv::new_from_slice(combo_keys[1].key.as_slice())?;
    let shard1_nonce = Nonce::from_slice(combo_keys[1].nonce.as_slice());
    let part_count = relevant_fragments.len() - 1;

    let mut pri_key_enc_parts: Vec<Vec<u8>> = split_data(
        shard0_cipher.decrypt(shard0_nonce, relevant_fragments[0].key.as_ref())?,
        part_count,
    );
    pri_key_enc_parts.insert(
        0,
        split_data(
            shard1_cipher.decrypt(shard1_nonce, relevant_fragments[1].key.as_ref())?,
            part_count,
        )[0]
        .clone(),
    );
    let mut pri_key = reassemble_data(pri_key_enc_parts);

    // while we're at it, reconstruct the ciphertext from the fragments
    let mut ciphertext_parts: Vec<Vec<u8>> =
        split_data(relevant_fragments[0].ciphertext.clone(), part_count);
    ciphertext_parts.insert(
        0,
        split_data(relevant_fragments[1].ciphertext.clone(), part_count)[0].clone(),
    );
    let ciphertext = reassemble_data(ciphertext_parts);

    // XXX debug start
    println!(
        "reconstructed encrypted fragments\n- pri_key_enc: {}\n- ciphertext: {}",
        hex::encode(pri_key.clone()),
        hex::encode(ciphertext.clone())
    );
    // XXX debug end

    // now we just need to unwrap any canaries from the primary key
    canaries.sort_by(|a, b| b.layer.cmp(&a.layer));
    for canary in &canaries {
        let canary_cipher = Aes256GcmSiv::new_from_slice(canary.key.key.as_slice())?;
        let canary_nonce = Nonce::from_slice(canary.key.nonce.as_slice());
        pri_key = canary_cipher.decrypt(canary_nonce, pri_key.as_ref())?;
        println!(
            "canary layer {} unwrapped from primary key\n- pri_key = {}",
            canary.layer,
            hex::encode(pri_key.clone())
        );
    }

    let pri_cipher = Aes256GcmSiv::new_from_slice(pri_key.as_slice())?;
    let pri_nonce = Nonce::from_slice(relevant_shards[0].pri_nonce.as_slice());
    let plaintext = pri_cipher.decrypt(pri_nonce, ciphertext.as_ref())?;

    let mut out_file = File::create(output_path)?;
    out_file.write_all(&plaintext)?;

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

fn reassemble_data(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut result = Vec::new();

    for part in parts {
        result.extend_from_slice(&part);
    }

    result
}

fn find_insert_index(haystack: &Vec<u8>, needle: u8) -> usize {
    match haystack.binary_search(&needle) {
        Ok(index) => index,
        Err(index) => index,
    }
}

fn remove_part(haystack: &Vec<u8>, parts: usize, idx: usize) -> Vec<u8> {
    if idx >= parts {
        panic!("out of bounds")
    }

    let split = split_data(haystack.clone(), parts);
    reassemble_data(
        split
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, v)| v)
            .collect::<Vec<Vec<u8>>>(),
    )
}
