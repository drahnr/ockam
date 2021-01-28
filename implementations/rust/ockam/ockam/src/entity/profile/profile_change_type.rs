use crate::entity::profile::profile_change_type::create_key::CreateKeyChange;
use crate::entity::profile::profile_change_type::rotate_key::RotateKeyChange;
use serde::{Deserialize, Serialize};

pub mod create_key;
pub mod rotate_key;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProfileChangeType {
    CreateKey(CreateKeyChange),
    RotateKey(RotateKeyChange),
}
