use clap::{arg, command, value_parser, Command, ArgAction};
use clap::error::ErrorKind;

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

            let quorum: u8 = *sub_matches.get_one("quorum").unwrap();
            let trustees: u8 = *sub_matches.get_one("trustees").unwrap();

            if quorum > trustees {
                cmd.error(
                    ErrorKind::ValueValidation,
                    "Quorum cannot be greater than number of trustees."
                )
                .exit()
            }

        },
        Some(("decrypt", _)) => println!(
            "'ddwill decrypt' was used",
        ),
        _ => unreachable!("invalid subcommand")
    }

}
