use super::{canary::Canary, shard::Shard};
use bincode;
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Debug)]
pub enum Deliverable {
    Canary(Canary),
    Shard(Shard),
}

pub fn commit_deliverable(
    dir: &Path,
    file: &str,
    datum: &Deliverable,
) -> Result<(), std::io::Error> {
    let out_path = dir.join(file);
    info!("Writing out to {}", out_path.display());
    let mut out_file = File::create(out_path)?;

    let serialized = bincode::serialize(datum)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    out_file.write_all(&serialized)?;

    Ok(())
}

pub fn retrieve_deliverable(file: &PathBuf) -> Result<Deliverable, std::io::Error> {
    let mut in_file = File::open(file)?;
    let mut buf = Vec::new();
    in_file.read_to_end(&mut buf)?;

    let datum: Deliverable = bincode::deserialize(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(datum)
}
