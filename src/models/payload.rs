use super::{deliverable::Deliverable, meta::Meta};
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub meta: Meta,           // version info, trustee instructions, etc.
    pub deliverable: Vec<u8>, // the deliverable, generally either a canary or shard
}

impl Payload {
    pub fn new(meta: Meta, deliverable: &Deliverable) -> Self {
        Payload {
            meta: meta,
            deliverable: bincode::serialize(&deliverable).unwrap_or(Vec::new()),
        }
    }

    pub fn get_deliverable(&self) -> Result<Deliverable, std::io::Error> {
        let datum: Deliverable = bincode::deserialize(self.deliverable.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(datum)
    }

    pub fn import(file: &PathBuf) -> Result<Self, std::io::Error> {
        let mut in_file = File::open(file)?;
        let mut buf = Vec::new();
        in_file.read_to_end(&mut buf)?;

        let datum: Payload = bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(datum)
    }

    pub fn export(&self, dir: &Path, file: &str) -> Result<(), std::io::Error> {
        let out_path = dir.join(file);
        info!("Writing out to {}", out_path.display());
        let mut out_file = File::create(out_path)?;

        let serialized = bincode::serialize(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        out_file.write_all(&serialized)?;

        Ok(())
    }
}
