use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct EventIdentifier([u8; 32]);

impl AsRef<[u8]> for EventIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl EventIdentifier {
    pub fn from_hash(hash: [u8; 32]) -> Self {
        Self { 0: hash }
    }

    pub fn to_string_representation(&self) -> String {
        format!("E_ID.{}", hex::encode(&self.0))
    }
}
