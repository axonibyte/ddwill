use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    pub ver: String,  // the version of the software used to generate deliverables
    pub desc: String, // the plaintext description that should be used to guide trustees
}

impl Meta {
    pub fn new(ver: String, desc: String) -> Self {
        Meta {
            ver: ver,
            desc: desc,
        }
    }
}
