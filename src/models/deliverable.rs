use super::{canary::Canary, shard::Shard};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Deliverable {
    Canary(Canary),
    Shard(Shard),
}
