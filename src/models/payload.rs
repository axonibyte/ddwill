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
    pub fn new(meta: Meta, deliverable: &Deliverable) -> Result<Self, std::io::Error> {
        let deliverable = bincode::serde::encode_to_vec(deliverable, bincode::config::standard())
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Payload { meta, deliverable })
    }

    pub fn get_deliverable(&self) -> Result<Deliverable, std::io::Error> {
        let (datum, _): (Deliverable, usize) =
            bincode::serde::decode_from_slice(&self.deliverable, bincode::config::standard())
                .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(datum)
    }

    pub fn import(file: &PathBuf) -> Result<Self, std::io::Error> {
        let mut in_file = File::open(file)?;
        let mut buf = Vec::new();
        in_file.read_to_end(&mut buf)?;

        let (datum, _): (Payload, usize) =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard())
                .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(datum)
    }

    pub fn export(&self, dir: &Path, file: &str) -> Result<(), std::io::Error> {
        let out_path = dir.join(file);
        info!("Writing out to {}", out_path.display());
        let mut out_file = File::create(out_path)?;

        let serialized = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| io::Error::other(e.to_string()))?;
        out_file.write_all(&serialized)?;

        Ok(())
    }
}
