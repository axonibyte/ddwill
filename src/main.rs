use aes_gcm_siv:: {
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce
};
use clap::{
    error::ErrorKind,
    arg, command, value_parser, Command, ArgAction
};
use std::io;

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

            let key = Aes256GcmSiv::generate_key(&mut OsRng);
            let cipher = Aes256GcmSiv::new(&key);
            let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
            let ciphertext_res = cipher.encrypt(nonce, b"plaintext message".as_ref());

            match ciphertext_res {
                Ok(ciphertext) => {
                    println!("Encryption successful: {:?}", ciphertext);


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
                },
                Err(e) => {
                    eprintln!("Encryption failed: {}", e);
                    //Err(e)
                }
            }

        },
        Some(("decrypt", _)) => println!(
            "'ddwill decrypt' was used",
        ),
        _ => unreachable!("invalid subcommand")
    }
}