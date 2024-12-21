use aes_gcm_siv:: {
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Error, Nonce
};
use clap::{
    error::ErrorKind,
    arg, command, value_parser, Command, ArgAction
};
use std::{
    boxed::Box,
    fs, io
};

#[derive(Debug)]
struct Shard { // the thing that gets sent to the trustee
    fragments: Vec<Fragment>, // possible permutations of quorum
    key: Key, // this user's key for fragments in other shards
    owner: u8 // this user's ordinal
}

#[derive(Debug)]
struct Fragment { // a particular piece of the file, only in trustee shards
  ciphertext: Vec<u8>, // a piece of the ciphertext
  key: Key, // part of the primary key, currently encrypted
  owners: Vec<u8> // ordinals of trustees needed to decrypt this fragment
}

#[derive(Debug)]
struct Key { // used for both canary and trustee keys
  key: Vec<u8>, // secret key
  nonce: Vec<u8> // nonce for secret key
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

fn handle_encrypt(required_count: u8, quorum_count: u8, trustees_count: u8) -> Result<(), Error> {

    let pri_key = Aes256GcmSiv::generate_key(&mut OsRng);
    let pri_cipher = Aes256GcmSiv::new(&pri_key);
    let pri_nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = pri_cipher.encrypt(pri_nonce, b"plaintext message".as_ref())?;
    println!("Encryption successful: {:?}", ciphertext);

    Ok(())
}

fn handle_decrypt() -> Result<(), Error> {

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