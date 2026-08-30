mod errors;
mod models;

use aes_gcm_siv::{
    aead::{Aead, Generate, KeyInit},
    Aes256GcmSiv, Key as AesKey, Nonce,
};
use clap::{arg, command, error::ErrorKind, value_parser, ArgAction, Command};
use crypto_common::InvalidLength;
use env_logger::Env;
use errors::crypto_error::CryptoError;
use itertools::Itertools;
use log::{debug, error, info, warn};
use models::{
    canary::Canary, deliverable::Deliverable, fragment::Fragment, key::Key, meta::Meta, part::Part,
    payload::Payload, shard::Shard,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    process::ExitCode,
};

fn main() -> ExitCode {
    // RUST_LOG wins if set; otherwise debug builds are chatty and release
    // builds are not
    let default_level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(default_level)).init();

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
                )
                .arg(
                    arg!(--description <DESCRIPTION>)
                        .required(false)
                        .default_value("")
                        .action(ArgAction::Set),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt the ciphertext and recover the will.")
                .arg(arg!(--indir <DIR>).required(true).action(ArgAction::Set))
                .arg(arg!(--outfile <FILE>).required(true).action(ArgAction::Set)),
        )
        .subcommand(
            Command::new("info")
                .about("Provide information about a particular deliverable.")
                .arg(arg!(--infile <FILE>).required(true).action(ArgAction::Set)),
        );
    let matches = cmd.get_matches_mut();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let required_count: u8 = *sub_matches.get_one("canaries").unwrap();
            let quorum_count: u8 = *sub_matches.get_one("quorum").unwrap();
            let trustees_count: u8 = *sub_matches.get_one("trustees").unwrap();
            let input_file = Path::new(sub_matches.get_one::<String>("infile").unwrap());
            let output_dir = Path::new(sub_matches.get_one::<String>("outdir").unwrap());

            let meta: Meta = Meta::new(
                env!("CARGO_PKG_VERSION").to_string(),
                sub_matches
                    .get_one::<String>("description")
                    .unwrap()
                    .to_string(),
            );

            if 2 > trustees_count {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "You must have at least two (2) trustees.",
                )
                .exit()
            }

            if 2 > quorum_count {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "You must have a quorum of at least two (2).",
                )
                .exit()
            }

            if quorum_count > trustees_count {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Quorum cannot be greater than number of trustees.",
                )
                .exit()
            }

            match fragments_per_shard(trustees_count, quorum_count) {
                Some(count) if count <= MAX_FRAGMENTS_PER_SHARD => {
                    debug!("each shard will carry {} fragments", count);
                }
                count => cmd
                    .error(
                        ErrorKind::ValueValidation,
                        format!(
                            "{} trustees with a quorum of {} needs {} fragments per shard, \
                             which is more than the limit of {}. Each shard carries one \
                             fragment for every quorum its trustee could be part of, i.e. \
                             C(trustees - 1, quorum - 1); use fewer trustees, or a quorum \
                             closer to 2 or to the trustee count.",
                            trustees_count,
                            quorum_count,
                            count
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "far too many".to_string()),
                            MAX_FRAGMENTS_PER_SHARD
                        ),
                    )
                    .exit(),
            }

            if !input_file.exists() {
                cmd.error(ErrorKind::ValueValidation, "Input file does not exist.")
                    .exit();
            } else if !input_file.is_file() {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Specified input exists but is not a file.",
                )
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
                &meta,
            );
            match enc_res {
                Ok(()) => {
                    info!("Encryption successful!");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!("Encryption failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Some(("decrypt", sub_matches)) => {
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
                    info!("Decryption successful!");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!("Decryption failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Some(("info", sub_matches)) => {
            let input_file = Path::new(sub_matches.get_one::<String>("infile").unwrap());

            if !input_file.exists() {
                cmd.error(ErrorKind::ValueValidation, "Input file does not exist.")
                    .exit();
            } else if !input_file.is_file() {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Specified file exists but is not a file.",
                )
                .exit();
            }

            match describe_payload(input_file) {
                Ok(report) => {
                    info!("{}", report);
                    ExitCode::SUCCESS
                }
                Err(report) => {
                    info!("{}", report);
                    ExitCode::FAILURE
                }
            }
        }

        _ => unreachable!("invalid subcommand"),
    }
}

/// The most fragments a single shard is allowed to carry. Fragments are small
/// (well under 100 bytes each), so this keeps shards under ~10 MB regardless of
/// the size of the will.
const MAX_FRAGMENTS_PER_SHARD: u64 = 100_000;

/// How many fragments each shard carries: C(trustees - 1, quorum - 1), one for
/// every quorum the trustee could be part of. None if it overflows u64.
fn fragments_per_shard(trustees: u8, quorum: u8) -> Option<u64> {
    if quorum == 0 || quorum > trustees {
        return None;
    }
    let n = (trustees - 1) as u64;
    let k = (quorum - 1) as u64;
    let k = k.min(n - k); // C(n, k) == C(n, n - k); fewer steps
    let mut result: u64 = 1;
    for i in 0..k {
        // result * (n - i) / (i + 1) is exact at every step
        result = result.checked_mul(n - i)? / (i + 1);
    }
    Some(result)
}

fn handle_encrypt(
    canary_count: u8,
    quorum_count: u8,
    trustees_count: u8,
    input_path: &Path,
    output_path: &Path,
    meta: &Meta,
) -> Result<(), CryptoError> {
    info!("Kicking off encryption workflow.");

    // generate primary cryptovariables for encryption
    let pri_key = AesKey::<Aes256GcmSiv>::generate();
    let pri_cipher = Aes256GcmSiv::new(&pri_key);
    let pri_nonce = Nonce::generate();
    let pri_nonce_buf = pri_nonce.to_vec();

    // grab the plaintext to be encrypted
    let mut input_file = fs::File::open(input_path)?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;

    // encrypt the plaintext with the primary key
    let ciphertext = pri_cipher.encrypt(&pri_nonce, plaintext.as_slice())?;
    let mut pri_key_enc = pri_key.as_slice().to_vec();

    debug!(
        "encrypted {} bytes of plaintext into {} bytes of ciphertext",
        plaintext.len(),
        ciphertext.len()
    );

    let mut canaries: Vec<Canary> = Vec::new();
    for i in 0..canary_count {
        // generate a set of canary cryptovariables for encryption
        let canary_key = AesKey::<Aes256GcmSiv>::generate();
        let canary_cipher = Aes256GcmSiv::new(&canary_key);
        let canary_nonce = Nonce::generate();

        // encrypt the primary key with a canary key
        pri_key_enc = canary_cipher.encrypt(&canary_nonce, pri_key_enc.as_slice())?;

        debug!(
            "canary {} wraps the primary key ({} bytes now)",
            i,
            pri_key_enc.len()
        );

        // save the canary in memory
        canaries.push(Canary::new(
            Key::new(canary_key.to_vec(), canary_nonce.to_vec()),
            i,
        ));
    }

    // the ciphertext is split into one part per trustee; each trustee gets
    // every part except a window of (quorum - 1) consecutive parts starting
    // at their own ordinal, so no single shard carries the whole ciphertext
    // but any quorum of shards holds every part between them (each part is
    // absent from exactly quorum - 1 shards)
    let ciphertext_parts = split_data(ciphertext.clone(), trustees_count as usize);

    // create a shard to distribute to each trustee
    let mut shards: Vec<Shard> = (0..trustees_count)
        .map(|i| {
            // each shard has a unique nonce, which will be XORed with the other
            // nonces to create a per-fragment nonce
            let frag_nonce = Nonce::generate().to_vec();
            Shard::new(
                // each trustee has a unique key and a copy of the primary nonce
                i,
                Key::new(AesKey::<Aes256GcmSiv>::generate().to_vec(), frag_nonce),
                pri_nonce_buf.clone(),
                held_parts(&ciphertext_parts, trustees_count, quorum_count, i),
                trustees_count,
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

            debug!("trustee {} gets a fragment for combo {:?}", i, combo);

            // build cipher, nonce from xored key combo
            let shard_cipher = Aes256GcmSiv::new_from_slice(&key_combo.key)?;
            let shard_nonce = nonce_from(&key_combo.nonce)?;

            // the fragment is the (canary-wrapped) primary key, sealed under
            // the combo key/nonce, plus the list of inner trustees whose keys
            // make up that combo; it can only be opened once all of them have
            // handed in their shards, which together with this one is a quorum
            let frag = Fragment::new(
                shard_cipher.encrypt(&shard_nonce, pri_key_enc.as_slice())?,
                combo.clone(),
            );

            // this frag gets pushed to the shard for the outer trustee
            shards[i as usize].fragments.push(frag);
        }
    }

    // serialization time!
    for canary in canaries {
        let layer = canary.layer;
        let payload: Payload = Payload::new(meta.clone(), &Deliverable::Canary(canary))?;
        payload.export(output_path, &format!("canary_{}.will", layer))?;
    }

    for shard in shards {
        let owner = shard.owner;
        let payload: Payload = Payload::new(meta.clone(), &Deliverable::Shard(shard))?;
        payload.export(output_path, &format!("shard_{}.will", owner))?;
    }

    Ok(())
}

fn handle_decrypt(input_path: &Path, output_path: &Path) -> Result<(), CryptoError> {
    let mut canaries: Vec<Canary> = Vec::new();
    let mut shards: Vec<Shard> = Vec::new();

    for entry in fs::read_dir(input_path)? {
        let file = entry?.path();
        if file.is_file() {
            match Payload::import(&file) {
                Ok(payload) => {
                    let ver: String = env!("CARGO_PKG_VERSION").to_string();
                    match payload.get_deliverable() {
                        Ok(Deliverable::Canary(canary)) => {
                            info!("Found a canary associated with layer {}.", canary.layer);
                            canaries.push(canary);
                        }
                        Ok(Deliverable::Shard(shard)) => {
                            info!("Found a shard belonging to Trustee no. {}.", shard.owner);
                            shards.push(shard);
                        }
                        Err(e) => {
                            if payload.meta.ver == ver {
                                error!("Discovered an malformed payload {}", file.display());
                                debug!("More information: {:?}", e);
                            } else {
                                error!("Discovered an incompatible payload {}", file.display());
                                error!(
                                    "Bad version: You're on v{} but the payload was made with v{}",
                                    ver, payload.meta.ver
                                );
                                debug!("More information: {:?}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Skipping file {} (it doesn't appear to be a valid payload)",
                        file.display()
                    );
                    debug!("More information: {:?}", e);
                }
            }
        }
    }

    // all canaries and shards are loaded;
    // we need a fragment from each of the trustees;
    // remember that the user may have provided greater or fewer files than
    // strictly required

    shards.sort_by_key(|shard| shard.owner);
    let shard_owners: Vec<u8> = shards.iter().map(|shard| shard.owner).collect();

    // we need one fragment whose other owners have all handed in their shards;
    // the first shard's fragments are as good as any, since every shard has a
    // fragment for every quorum its trustee could be part of
    let holder = shards
        .first()
        .ok_or_else(|| CryptoError::workflow_error("No shards were found."))?;
    let fragment = holder
        .fragments
        .iter()
        .find(|fragment| {
            fragment
                .owners
                .iter()
                .all(|owner| shard_owners.contains(owner))
        })
        .ok_or_else(|| CryptoError::workflow_error("No matching fragments were found."))?;

    // at this point, we have a quorum
    debug!(
        "using a fragment from trustee {} that needs trustees {:?}",
        holder.owner, fragment.owners
    );

    // the fragment holds the whole (canary-wrapped) primary key, sealed under
    // the XOR of the keys and nonces of the trustees it names
    let combo_key = Key::xor_keys(
        shards
            .iter()
            .filter(|shard| fragment.owners.contains(&shard.owner))
            .map(|shard| shard.key.clone())
            .collect::<Vec<Key>>()
            .as_slice(),
    );

    let combo_cipher = Aes256GcmSiv::new_from_slice(combo_key.key.as_slice())?;
    let combo_nonce = nonce_from(&combo_key.nonce)?;
    let mut pri_key = combo_cipher.decrypt(&combo_nonce, fragment.key.as_slice())?;

    // while we're at it, reconstruct the ciphertext from the parts scattered
    // across every shard we were given (a quorum is guaranteed to hold them all)
    let ciphertext = reassemble_ciphertext(&shards)?;

    debug!(
        "recovered {} bytes of wrapped primary key and {} bytes of ciphertext",
        pri_key.len(),
        ciphertext.len()
    );

    // now we just need to unwrap any canaries from the primary key
    canaries.sort_by_key(|canary| std::cmp::Reverse(canary.layer));
    for canary in &canaries {
        let canary_cipher = Aes256GcmSiv::new_from_slice(canary.key.key.as_slice())?;
        let canary_nonce = nonce_from(&canary.key.nonce)?;
        pri_key = canary_cipher.decrypt(&canary_nonce, pri_key.as_slice())?;
        debug!("canary layer {} unwrapped from primary key", canary.layer);
    }

    let pri_cipher = Aes256GcmSiv::new_from_slice(pri_key.as_slice())?;
    let pri_nonce = nonce_from(&holder.pri_nonce)?;
    let plaintext = pri_cipher.decrypt(&pri_nonce, ciphertext.as_slice())?;

    let mut out_file = File::create(output_path)?;
    out_file.write_all(&plaintext)?;

    Ok(())
}

/// Describe a payload file for whoever is holding it. `Ok` carries the report
/// for a usable canary or shard; `Err` carries the report for anything else.
fn describe_payload(input_path: &Path) -> Result<String, String> {
    let ver = env!("CARGO_PKG_VERSION");
    let payload = match Payload::import(&input_path.to_path_buf()) {
        Ok(payload) => payload,
        Err(e) => {
            debug!("Additional information: {:?}", e);
            return Err(format!(
                "File {} does not seem to be related at all to this software.",
                input_path.display()
            ));
        }
    };

    let desc = if payload.meta.desc.trim().is_empty() {
        "N/A"
    } else {
        payload.meta.desc.trim()
    };

    match payload.get_deliverable() {
        Ok(Deliverable::Canary(canary)) => Ok(format!(
            "\n- File {} appears to be a canary.\n\
             - All canaries are required for decryption. They're \
             designed to be hidden somewhere physical (like a \
             safety deposit box or as a website canary), fully \
             controlled by the creator until death (presumably).\n\
             - This canary's ID is {}, but you won't be able to tell \
             from this file how many canaries there are in total \
             (unless the creator put it in the description).\n\
             - Description: {}",
            input_path.display(),
            canary.layer,
            desc
        )),
        Ok(Deliverable::Shard(shard)) => {
            let quorum = shard
                .fragments
                .first()
                .map(|fragment| fragment.owners.len() + 1)
                .unwrap_or(0);
            Ok(format!(
                "\n- File {} appears to be a shard.\n\
                 - A quorum of shards are required for decryption. In \
                 other words, a bunch may have been entrusted to various \
                 folks but only a certain number are required for \
                 decryption.\n\
                 - This is shard {} of the {} that were handed out, and \
                 any {} of them (plus every canary) are enough to decrypt. \
                 Treat this file like a physical key: anyone who has it \
                 has your share.\n\
                 - Description: {}",
                input_path.display(),
                shard.owner,
                shard.part_count,
                quorum,
                desc
            ))
        }
        Err(e) => {
            debug!("Additional information: {:?}", e);
            if payload.meta.ver == ver {
                Err(format!(
                    "\n- File {} appears to be a malformed payload.\n\
                     - It was probably generated with this version of \
                     the software, though (currently v{}).\n\
                     - Your best bet is to hope that there are other \
                     trustees with intact shards.",
                    input_path.display(),
                    ver
                ))
            } else {
                Err(format!(
                    "\n- File {} appears to be an incompatible payload.\n\
                     - It was most likely created with v{} of this software, \
                     but you're currently running v{}.",
                    input_path.display(),
                    payload.meta.ver,
                    ver
                ))
            }
        }
    }
}

/// Build a nonce from stored bytes, refusing anything but exactly the right
/// number of them (a truncated or corrupted payload, most likely).
fn nonce_from(bytes: &[u8]) -> Result<Nonce, CryptoError> {
    Nonce::try_from(bytes).map_err(|_| CryptoError::InvalidLength(InvalidLength))
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

/// Pick the ciphertext parts that trustee `owner` gets to hold: everything
/// except the `quorum - 1` consecutive parts (wrapping around) that start at
/// their own ordinal. Every part is therefore absent from exactly `quorum - 1`
/// shards, which is the largest gap that still lets any quorum cover all of it.
fn held_parts(parts: &[Vec<u8>], trustees: u8, quorum: u8, owner: u8) -> Vec<Part> {
    let t = trustees as usize;
    let omitted: Vec<usize> = (0..(quorum as usize - 1))
        .map(|k| (owner as usize + k) % t)
        .collect();
    parts
        .iter()
        .enumerate()
        .filter(|(idx, _)| !omitted.contains(idx))
        .map(|(idx, data)| Part::new(idx as u8, data.clone()))
        .collect()
}

/// Stitch the ciphertext back together from whichever shards carry each part.
fn reassemble_ciphertext(shards: &[Shard]) -> Result<Vec<u8>, CryptoError> {
    let part_count = match shards.first() {
        Some(shard) => shard.part_count as usize,
        None => return Err(CryptoError::workflow_error("No shards were found.")),
    };

    if shards.iter().any(|s| s.part_count as usize != part_count) {
        return Err(CryptoError::workflow_error(
            "Shards disagree on how the ciphertext was split; they may not be from the same encryption run.",
        ));
    }

    let mut parts: Vec<Option<&[u8]>> = vec![None; part_count];
    for shard in shards {
        for part in &shard.parts {
            let idx = part.index as usize;
            if idx >= part_count {
                return Err(CryptoError::workflow_error(&format!(
                    "Shard {} carries ciphertext part {} but only {} parts exist.",
                    shard.owner, idx, part_count
                )));
            }
            match parts[idx] {
                None => parts[idx] = Some(part.data.as_slice()),
                Some(existing) if existing != part.data.as_slice() => {
                    return Err(CryptoError::workflow_error(&format!(
                        "Shards carry conflicting copies of ciphertext part {}; they may not be from the same encryption run.",
                        idx
                    )));
                }
                Some(_) => {}
            }
        }
    }

    let missing: Vec<usize> = parts
        .iter()
        .enumerate()
        .filter(|(_, p)| p.is_none())
        .map(|(idx, _)| idx)
        .collect();
    if !missing.is_empty() {
        return Err(CryptoError::workflow_error(&format!(
            "Ciphertext parts {:?} are missing; the shards provided do not form a quorum.",
            missing
        )));
    }

    Ok(parts
        .into_iter()
        .flat_map(|p| p.unwrap().to_vec())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use std::path::PathBuf;
    use tempfile::{tempdir, TempDir};

    /// Deterministic, non-repeating bytes so misordered parts are detectable.
    fn sample_plaintext(len: usize) -> Vec<u8> {
        let mut state: u32 = 0x2545_F491;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    struct Run {
        _root: TempDir,
        outdir: PathBuf,
        plaintext: Vec<u8>,
        trustees: u8,
        canaries: u8,
    }

    fn encrypt(plaintext: Vec<u8>, trustees: u8, quorum: u8, canaries: u8) -> Run {
        let root = tempdir().unwrap();
        let infile = root.path().join("will.txt");
        fs::write(&infile, &plaintext).unwrap();
        let outdir = root.path().join("out");
        fs::create_dir(&outdir).unwrap();
        handle_encrypt(
            canaries,
            quorum,
            trustees,
            &infile,
            &outdir,
            &Meta::new("test".to_string(), String::new()),
        )
        .unwrap();
        Run {
            _root: root,
            outdir,
            plaintext,
            trustees,
            canaries,
        }
    }

    /// Decrypt using exactly the given shards (plus the given canaries).
    fn decrypt_with(run: &Run, shards: &[u8], canaries: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let attempt = tempdir().unwrap();
        for s in shards {
            let name = format!("shard_{}.will", s);
            fs::copy(run.outdir.join(&name), attempt.path().join(&name)).unwrap();
        }
        for c in canaries {
            let name = format!("canary_{}.will", c);
            fs::copy(run.outdir.join(&name), attempt.path().join(&name)).unwrap();
        }
        let outfile = attempt.path().join("recovered.txt");
        handle_decrypt(attempt.path(), &outfile)?;
        Ok(fs::read(&outfile).unwrap())
    }

    fn load_shards(run: &Run) -> Vec<Shard> {
        (0..run.trustees)
            .map(|i| {
                let payload =
                    Payload::import(&run.outdir.join(format!("shard_{}.will", i))).unwrap();
                match payload.get_deliverable().unwrap() {
                    Deliverable::Shard(shard) => shard,
                    other => panic!("expected a shard, got {:?}", other),
                }
            })
            .collect()
    }

    const GRID: &[(u8, u8, u8)] = &[
        (2, 2, 0),
        (3, 2, 1),
        (3, 3, 0),
        (5, 3, 2),
        (6, 6, 1),
        (7, 4, 0),
        (9, 2, 1),
    ];

    #[test]
    fn every_quorum_recovers_the_plaintext() {
        for &(t, q, c) in GRID {
            let run = encrypt(sample_plaintext(1_000), t, q, c);
            let all_canaries: Vec<u8> = (0..c).collect();
            for quorum in (0..t).combinations(q as usize) {
                let recovered = decrypt_with(&run, &quorum, &all_canaries).unwrap_or_else(|e| {
                    panic!("t={} q={} c={} shards {:?}: {}", t, q, c, quorum, e)
                });
                assert_eq!(
                    recovered, run.plaintext,
                    "t={} q={} c={} shards {:?}",
                    t, q, c, quorum
                );
            }
        }
    }

    #[test]
    fn extra_shards_beyond_quorum_are_fine() {
        let run = encrypt(sample_plaintext(500), 5, 3, 1);
        let recovered = decrypt_with(&run, &[0, 1, 2, 3, 4], &[0]).unwrap();
        assert_eq!(recovered, run.plaintext);
    }

    #[test]
    fn every_subquorum_fails_without_writing_output() {
        for &(t, q, c) in GRID {
            let run = encrypt(sample_plaintext(300), t, q, c);
            let all_canaries: Vec<u8> = (0..c).collect();
            for size in 1..q as usize {
                for subset in (0..t).combinations(size) {
                    let attempt = tempdir().unwrap();
                    for s in &subset {
                        let name = format!("shard_{}.will", s);
                        fs::copy(run.outdir.join(&name), attempt.path().join(&name)).unwrap();
                    }
                    for cn in &all_canaries {
                        let name = format!("canary_{}.will", cn);
                        fs::copy(run.outdir.join(&name), attempt.path().join(&name)).unwrap();
                    }
                    let outfile = attempt.path().join("recovered.txt");
                    let res = handle_decrypt(attempt.path(), &outfile);
                    assert!(
                        res.is_err(),
                        "t={} q={} shards {:?} should not decrypt",
                        t,
                        q,
                        subset
                    );
                    assert!(
                        !outfile.exists(),
                        "t={} q={} shards {:?} wrote output",
                        t,
                        q,
                        subset
                    );
                }
            }
        }
    }

    #[test]
    fn missing_or_extra_canary_fails() {
        let run = encrypt(sample_plaintext(200), 4, 2, 2);
        assert!(decrypt_with(&run, &[0, 1], &[0]).is_err());
        assert!(decrypt_with(&run, &[0, 1], &[1]).is_err());
        assert!(decrypt_with(&run, &[0, 1], &[]).is_err());
        assert!(decrypt_with(&run, &[0, 1], &[0, 1]).is_ok());
        assert_eq!(run.canaries, 2);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let run = encrypt(Vec::new(), 4, 3, 0);
        assert_eq!(
            decrypt_with(&run, &[1, 2, 3], &[]).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn ciphertext_partition_is_consistent_for_every_trustee() {
        for &(t, q, c) in GRID {
            let run = encrypt(sample_plaintext(997), t, q, c);
            let shards = load_shards(&run);
            let ciphertext_len = run.plaintext.len() + 16; // GCM-SIV tag

            let mut absent_from = vec![0usize; t as usize];
            let mut held_bytes = 0usize;
            for shard in &shards {
                assert_eq!(shard.part_count, t, "part_count should equal trustee count");
                assert_eq!(
                    shard.parts.len(),
                    (t - q + 1) as usize,
                    "t={} q={} shard {} holds wrong number of parts",
                    t,
                    q,
                    shard.owner
                );
                let held: Vec<u8> = shard.parts.iter().map(|p| p.index).collect();
                assert!(
                    held.iter().all_unique(),
                    "duplicate part on shard {}",
                    shard.owner
                );
                for idx in 0..t {
                    if !held.contains(&idx) {
                        absent_from[idx as usize] += 1;
                    }
                }
                held_bytes += shard.parts.iter().map(|p| p.data.len()).sum::<usize>();
            }

            // no single shard has everything (this is the point), and every
            // part is absent from exactly q-1 shards (so any q shards cover it)
            assert!(q >= 2);
            for (idx, count) in absent_from.iter().enumerate() {
                assert_eq!(
                    *count,
                    (q - 1) as usize,
                    "t={} q={} part {} is absent from {} shards",
                    t,
                    q,
                    idx,
                    count
                );
            }

            // the ciphertext is carried once per held part, not once per fragment
            assert_eq!(held_bytes, (t - q + 1) as usize * ciphertext_len);
        }
    }

    #[test]
    fn fragments_carry_the_sealed_key_and_fragment_count_is_combinatorial() {
        for &(t, q, c) in GRID {
            let run = encrypt(sample_plaintext(100), t, q, c);
            for shard in load_shards(&run) {
                assert_eq!(
                    shard.fragments.len() as u64,
                    fragments_per_shard(t, q).unwrap(),
                    "t={} q={}",
                    t,
                    q
                );
                for frag in &shard.fragments {
                    assert_eq!(frag.owners.len(), (q - 1) as usize);
                    assert!(!frag.owners.contains(&shard.owner));
                    // 32-byte key, one 16-byte tag per canary wrap, one more
                    // for the combo seal; nothing else
                    assert_eq!(frag.key.len(), 32 + 16 * c as usize + 16);
                }
            }
        }
    }

    #[test]
    fn shards_from_different_runs_are_rejected() {
        let a = encrypt(sample_plaintext(400), 3, 2, 0);
        let b = encrypt(sample_plaintext(400), 3, 2, 0);
        let attempt = tempdir().unwrap();
        fs::copy(
            a.outdir.join("shard_0.will"),
            attempt.path().join("shard_0.will"),
        )
        .unwrap();
        fs::copy(
            b.outdir.join("shard_1.will"),
            attempt.path().join("shard_1.will"),
        )
        .unwrap();
        let outfile = attempt.path().join("recovered.txt");
        assert!(handle_decrypt(attempt.path(), &outfile).is_err());
        assert!(!outfile.exists());
    }

    #[test]
    fn describe_reports_shards_and_canaries_truthfully() {
        let run = encrypt(sample_plaintext(50), 5, 3, 1);
        let shard = describe_payload(&run.outdir.join("shard_2.will")).unwrap();
        assert!(shard.contains("appears to be a shard"));
        assert!(shard.contains("shard 2 of the 5 that were handed out"));
        assert!(shard.contains("any 3 of them"));
        let canary = describe_payload(&run.outdir.join("canary_0.will")).unwrap();
        assert!(canary.contains("appears to be a canary"));
        assert!(canary.contains("ID is 0"));
    }

    #[test]
    fn describe_names_the_right_versions_for_an_incompatible_payload() {
        let root = tempdir().unwrap();
        let payload = Payload {
            meta: Meta::new("0.0.1".to_string(), String::new()),
            deliverable: vec![0xff; 8], // not a deliverable at all
        };
        payload.export(root.path(), "old.will").unwrap();
        let report = describe_payload(&root.path().join("old.will")).unwrap_err();
        assert!(report.contains("incompatible"), "{}", report);
        assert!(
            report.contains("created with v0.0.1 of this software"),
            "{}",
            report
        );
        assert!(
            report.contains(&format!("running v{}", env!("CARGO_PKG_VERSION"))),
            "{}",
            report
        );
    }

    #[test]
    fn describe_rejects_files_that_are_not_payloads() {
        let root = tempdir().unwrap();
        let path = root.path().join("junk.bin");
        fs::write(&path, b"definitely not bincode of a payload").unwrap();
        assert!(describe_payload(&path).is_err());
    }

    #[test]
    fn fragments_per_shard_matches_binomial_coefficients() {
        assert_eq!(fragments_per_shard(2, 2), Some(1));
        assert_eq!(fragments_per_shard(5, 3), Some(6)); // C(4, 2)
        assert_eq!(fragments_per_shard(7, 4), Some(20)); // C(6, 3)
        assert_eq!(fragments_per_shard(12, 6), Some(462)); // C(11, 5)
        assert_eq!(fragments_per_shard(20, 10), Some(92_378)); // C(19, 9)
        assert_eq!(fragments_per_shard(20, 2), Some(19));
        assert_eq!(fragments_per_shard(20, 20), Some(1));
        assert_eq!(fragments_per_shard(40, 20), Some(68_923_264_410)); // C(39, 19)
        assert_eq!(fragments_per_shard(255, 128), None); // overflows u64
        assert_eq!(fragments_per_shard(3, 4), None);
        assert_eq!(fragments_per_shard(3, 0), None);
    }

    #[test]
    fn fragment_limit_admits_reasonable_shapes_and_refuses_explosive_ones() {
        assert!(fragments_per_shard(20, 10).unwrap() <= MAX_FRAGMENTS_PER_SHARD);
        assert!(fragments_per_shard(21, 11).unwrap() > MAX_FRAGMENTS_PER_SHARD);
        assert!(fragments_per_shard(200, 2).unwrap() <= MAX_FRAGMENTS_PER_SHARD);
        assert!(fragments_per_shard(200, 199).unwrap() <= MAX_FRAGMENTS_PER_SHARD);
    }

    #[test]
    fn split_and_reassemble_are_inverses() {
        for len in 0..40usize {
            let data = sample_plaintext(len);
            for n in 1..=8usize {
                let parts = split_data(data.clone(), n);
                assert_eq!(parts.len(), n);
                assert!(parts.iter().all(|p| p.len() >= data.len() / n));
                assert!(parts.iter().all(|p| p.len() <= data.len() / n + 1));
                assert_eq!(parts.concat(), data);
            }
        }
    }
}
