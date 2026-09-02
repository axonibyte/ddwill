//! End-to-end checks against the built binary: exit codes and file effects.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn ddwill(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ddwill"))
        .args(args)
        .env("RUST_LOG", "info")
        .output()
        .expect("failed to run ddwill")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn encrypt_args(dir: &Path, t: &str, q: &str, c: &str, extra: &[&str]) -> Output {
    let infile = dir.join("will.txt");
    fs::write(&infile, b"This is my will and testament :)\n").unwrap();
    let outdir = dir.join("out");
    let mut args = vec![
        "encrypt",
        "--infile",
        infile.to_str().unwrap(),
        "--outdir",
        outdir.to_str().unwrap(),
        "--canaries",
        c,
        "--trustees",
        t,
        "--quorum",
        q,
    ];
    args.extend_from_slice(extra);
    ddwill(&args)
}

/// Encrypt without recovery codes: the pre-existing flow.
fn encrypt(dir: &Path, t: &str, q: &str, c: &str) -> Output {
    encrypt_args(dir, t, q, c, &["--no-codes"])
}

fn copy_into(from: &Path, to: &Path, names: &[&str]) {
    fs::create_dir_all(to).unwrap();
    for name in names {
        fs::copy(from.join(name), to.join(name)).unwrap();
    }
}

#[test]
fn encrypt_then_decrypt_exits_zero_and_round_trips() {
    let root = tempfile::tempdir().unwrap();
    let out = encrypt(root.path(), "4", "3", "1");
    assert!(out.status.success(), "{}", stderr(&out));

    let q = root.path().join("q");
    copy_into(
        &root.path().join("out"),
        &q,
        &[
            "canary_0.will",
            "shard_0.will",
            "shard_2.will",
            "shard_3.will",
        ],
    );
    let recovered = root.path().join("recovered.txt");
    let out = ddwill(&[
        "decrypt",
        "--indir",
        q.to_str().unwrap(),
        "--outfile",
        recovered.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fs::read(recovered).unwrap(),
        fs::read(root.path().join("will.txt")).unwrap()
    );
}

#[test]
fn decrypt_below_quorum_exits_nonzero_and_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    assert!(encrypt(root.path(), "4", "3", "0").status.success());

    let q = root.path().join("q");
    copy_into(
        &root.path().join("out"),
        &q,
        &["shard_0.will", "shard_1.will"],
    );
    let recovered = root.path().join("recovered.txt");
    let out = ddwill(&[
        "decrypt",
        "--indir",
        q.to_str().unwrap(),
        "--outfile",
        recovered.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("Decryption failed"));
    assert!(!recovered.exists());
}

#[test]
fn decrypt_with_missing_canary_exits_nonzero() {
    let root = tempfile::tempdir().unwrap();
    assert!(encrypt(root.path(), "3", "2", "2").status.success());

    let q = root.path().join("q");
    copy_into(
        &root.path().join("out"),
        &q,
        &["canary_0.will", "shard_0.will", "shard_1.will"],
    );
    let recovered = root.path().join("recovered.txt");
    let out = ddwill(&[
        "decrypt",
        "--indir",
        q.to_str().unwrap(),
        "--outfile",
        recovered.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!recovered.exists());
}

#[test]
fn decrypt_of_empty_directory_exits_nonzero() {
    let root = tempfile::tempdir().unwrap();
    let empty = root.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let out = ddwill(&[
        "decrypt",
        "--indir",
        empty.to_str().unwrap(),
        "--outfile",
        root.path().join("x").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn info_exits_zero_for_a_shard_and_nonzero_for_junk() {
    let root = tempfile::tempdir().unwrap();
    assert!(encrypt(root.path(), "3", "2", "0").status.success());

    let out = ddwill(&[
        "info",
        "--infile",
        root.path().join("out/shard_1.will").to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("appears to be a shard"));

    let junk = root.path().join("junk.bin");
    fs::write(&junk, b"nope").unwrap();
    let out = ddwill(&["info", "--infile", junk.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn invalid_parameters_exit_with_usage_error() {
    let root = tempfile::tempdir().unwrap();
    // quorum larger than trustees is a usage error (clap's exit code 2)
    let out = encrypt(root.path(), "3", "4", "0");
    assert_eq!(out.status.code(), Some(2));
    assert!(!root.path().join("out").exists());
}

#[test]
fn explosive_fragment_counts_are_refused_before_any_work() {
    let root = tempfile::tempdir().unwrap();
    let out = encrypt(root.path(), "40", "20", "0");
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("fragments per shard"),
        "{}",
        stderr(&out)
    );
    assert!(!root.path().join("out").exists());
}

#[test]
fn recovery_codes_are_printed_and_required() {
    let root = tempfile::tempdir().unwrap();
    let out = encrypt_args(root.path(), "2", "2", "0", &[]);
    assert!(out.status.success(), "{}", stderr(&out));

    // codes go to stdout, one per shard
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let codes: Vec<String> = stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("shard "))
        .map(|rest| rest.split_once(": ").unwrap().1.to_string())
        .collect();
    assert_eq!(codes.len(), 2, "{}", stdout);

    // without codes, the files are not enough
    let recovered = root.path().join("recovered.txt");
    let outdir = root.path().join("out");
    let out = ddwill(&[
        "decrypt",
        "--indir",
        outdir.to_str().unwrap(),
        "--outfile",
        recovered.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("locked"), "{}", stderr(&out));
    assert!(!recovered.exists());

    // with the codes, everything recovers
    let out = ddwill(&[
        "decrypt",
        "--indir",
        outdir.to_str().unwrap(),
        "--outfile",
        recovered.to_str().unwrap(),
        "--code",
        &codes[0],
        "--code",
        &codes[1],
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fs::read(recovered).unwrap(),
        fs::read(root.path().join("will.txt")).unwrap()
    );
}
