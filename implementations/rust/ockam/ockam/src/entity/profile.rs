mod identifier;
pub use identifier::*;

mod change;
pub use change::*;

pub mod profile_change;
pub mod profile_change_type;
mod profile_helpers;
pub mod proof;

pub mod event_identifier;
mod verification;
use crate::entity::event_identifier::EventIdentifier;
use crate::entity::profile::profile_change::{ProfileKeyPurpose, ProfileKeyType};
use crate::entity::profile_change_type::ProfileChangeType::{CreateKey, RotateKey};
use crate::error::OckamError;
use hashbrown::HashMap;
use ockam_core::Error;
use ockam_vault_core::hash_vault::HashVault;
use ockam_vault_core::kid_vault::KidVault;
use ockam_vault_core::secret::Secret;
use ockam_vault_core::secret_vault::SecretVault;
use ockam_vault_core::signer_vault::SignerVault;
use ockam_vault_core::verifier_vault::VerifierVault;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
pub use verification::*;

pub const OCKAM_NO_EVENT: &[u8] = "OCKAM_NO_EVENT".as_bytes();
pub const OCKAM_PROFILE_VERSION: u8 = 1;

pub trait ProfileVault:
    SecretVault + KidVault + HashVault + SignerVault + VerifierVault + Debug
{
}

impl<D> ProfileVault for D where
    D: SecretVault + KidVault + HashVault + SignerVault + VerifierVault + Debug
{
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct KeyAttributes {
    label: String,
    key_type: ProfileKeyType,
    key_purpose: ProfileKeyPurpose,
}

impl KeyAttributes {
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn key_type(&self) -> ProfileKeyType {
        self.key_type
    }
    pub fn key_purpose(&self) -> ProfileKeyPurpose {
        self.key_purpose
    }
}

impl KeyAttributes {
    pub fn new(label: String, key_type: ProfileKeyType, key_purpose: ProfileKeyPurpose) -> Self {
        KeyAttributes {
            label,
            key_type,
            key_purpose,
        }
    }
}

pub type ProfileEventAttributes = HashMap<String, String>;

#[derive(Clone, Debug)]
pub struct Profile {
    identifier: ProfileIdentifier,
    change_history: ProfileChangeHistory,
    verification_policies: Vec<ProfileVerificationPolicy>,
    vault: Arc<Mutex<dyn ProfileVault>>,
}

impl Profile {
    pub fn identifier(&self) -> &ProfileIdentifier {
        &self.identifier
    }
    pub fn change_history(&self) -> &ProfileChangeHistory {
        &self.change_history
    }
    pub fn verification_policies(&self) -> &[ProfileVerificationPolicy] {
        &self.verification_policies
    }
}

impl Profile {
    pub fn new(
        identifier: ProfileIdentifier,
        change_history: ProfileChangeHistory,
        verification_policies: Vec<ProfileVerificationPolicy>,
        vault: Arc<Mutex<dyn ProfileVault>>,
    ) -> Self {
        Profile {
            identifier,
            change_history,
            verification_policies,
            vault,
        }
    }
}

impl Profile {
    pub fn create_with_key(
        key_attributes: KeyAttributes,
        attributes: Option<ProfileEventAttributes>,
        vault: Arc<Mutex<dyn ProfileVault>>,
    ) -> Result<Self, ockam_core::Error> {
        let prev_id;
        {
            let v = vault.lock().unwrap();
            prev_id = v.sha256(OCKAM_NO_EVENT)?;
        }

        let prev_id = EventIdentifier::from_hash(prev_id);
        let change_event = Self::create_key_event_static(
            prev_id,
            key_attributes.clone(),
            attributes,
            vault.clone(),
        )?;

        let change = Self::find_key_change_in_event(&change_event, &key_attributes).unwrap(); // FIXME
        let public_key = Self::get_change_public_key(&change)?;

        let v = vault.lock().unwrap();

        let public_kid = v.sha256(public_key.as_ref())?;
        let public_kid = ProfileIdentifier::from_hash(public_kid);

        let profile = Profile::new(
            public_kid,
            ProfileChangeHistory::new(vec![change_event]),
            Vec::new(),
            vault.clone(),
        );

        Ok(profile)
    }

    pub fn create_key(
        &mut self,
        key_attributes: KeyAttributes,
        attributes: Option<ProfileEventAttributes>,
    ) -> Result<(), ockam_core::Error> {
        let event = self.create_key_event(key_attributes, attributes)?;
        self.apply_no_verification(event)
    }

    pub fn rotate_key(
        &mut self,
        key_attributes: KeyAttributes,
        attributes: Option<ProfileEventAttributes>,
    ) -> Result<(), ockam_core::Error> {
        let event = self.rotate_key_event(key_attributes, attributes)?;
        self.apply_no_verification(event)
    }

    pub fn get_private_key(
        &self,
        key_attributes: KeyAttributes,
    ) -> Result<Secret, ockam_core::Error> {
        let event = self.find_last_key_event(&key_attributes)?;
        self.get_private_key_from_event(&key_attributes, event)
    }
}

impl Profile {
    fn check_consistency(_change_event: &ProfileChangeEvent) -> bool {
        // TODO: check event for consistency: e.g. you cannot rotate the same key twice during one event
        true
    }

    fn apply_no_verification(&mut self, change_event: ProfileChangeEvent) -> Result<(), Error> {
        if !Self::check_consistency(&change_event) {
            return Err(OckamError::InvalidInternalState.into());
        }

        self.change_history.push_event(change_event);

        Ok(())
    }

    pub fn apply(&mut self, change_event: ProfileChangeEvent) -> Result<(), Error> {
        self.verify(&change_event)?;

        self.apply_no_verification(change_event)
    }

    // WARNING: Checks only one event, assumes all previous events are verified
    pub fn verify(&self, change_event: &ProfileChangeEvent) -> Result<(), ockam_core::Error> {
        if !Self::check_consistency(&change_event) {
            return Err(OckamError::ConsistencyError.into());
        }

        // More than 1 change per event is not supported yet
        if change_event.changes().len() > 1 {
            return Err(OckamError::ComplexEventsAreNotSupported.into());
        }

        let changes = change_event.changes();
        let changes_binary =
            serde_bare::to_vec(&changes).map_err(|_| OckamError::BareError.into())?;

        let mut vault = self.vault.lock().unwrap();

        let event_id = vault.sha256(&changes_binary)?;
        let event_id = EventIdentifier::from_hash(event_id);

        if &event_id != change_event.identifier() {
            return Err(OckamError::EventIdDoesntMatch.into());
        }

        let change;
        if let Some(ch) = change_event.changes().first() {
            change = ch;
        } else {
            return Err(OckamError::EmptyChange.into());
        }

        let res = match change.change_type() {
            CreateKey(c) => {
                // Should have 1 self signature
                let self_signature = Self::get_self_signature(change_event)?;
                vault
                    .verify(self_signature.data(), c.public_key(), event_id.as_ref())
                    .is_ok()
            }
            RotateKey(c) => {
                // Should have 1 self signature and 1 prev signature
                let self_signature = Self::get_self_signature(change_event)?;
                if !vault
                    .verify(self_signature.data(), c.public_key(), event_id.as_ref())
                    .is_ok()
                {
                    false;
                }

                let prev_key_event = self.find_key_event_before(&event_id, c.key_attributes())?;
                let prev_key_change =
                    Self::find_key_change_in_event(prev_key_event, c.key_attributes()).unwrap(); // FIXME
                let public_key = Self::get_change_public_key(prev_key_change)?;

                let prev_signature = Self::get_prev_signature(change_event)?;
                vault
                    .verify(prev_signature.data(), public_key, event_id.as_ref())
                    .is_ok()
            }
        };

        if res {
            Ok(())
        } else {
            Err(OckamError::VerifyFailed.into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ockam_vault::software_vault::SoftwareVault;

    #[test]
    fn test_new() {
        let vault = SoftwareVault::default();
        let vault = Arc::new(Mutex::new(vault));
        let mut profile = Profile::create_with_key(
            KeyAttributes::new(
                "for Alice".to_string(),
                ProfileKeyType::Main,
                ProfileKeyPurpose::Kex,
            ),
            None,
            vault,
        )
        .unwrap();

        let _private_key_for_alice = profile
            .get_private_key(KeyAttributes::new(
                "for Alice".to_string(),
                ProfileKeyType::Main,
                ProfileKeyPurpose::Kex,
            ))
            .unwrap();

        profile
            .create_key(
                KeyAttributes::new(
                    "for Bob".to_string(),
                    ProfileKeyType::Main,
                    ProfileKeyPurpose::Kex,
                ),
                None,
            )
            .unwrap();

        let _private_key_for_bob = profile
            .get_private_key(KeyAttributes::new(
                "for Bob".to_string(),
                ProfileKeyType::Main,
                ProfileKeyPurpose::Kex,
            ))
            .unwrap();

        profile
            .rotate_key(
                KeyAttributes::new(
                    "for Bob".to_string(),
                    ProfileKeyType::Main,
                    ProfileKeyPurpose::Kex,
                ),
                None,
            )
            .unwrap();

        let _private_key_for_bob_new = profile
            .get_private_key(KeyAttributes::new(
                "for Bob".to_string(),
                ProfileKeyType::Main,
                ProfileKeyPurpose::Kex,
            ))
            .unwrap();

        for change_event in profile.change_history().as_ref() {
            let id = change_event.identifier().to_string_representation();
            if profile.verify(change_event).is_ok() {
                println!("{} is valid", id);
            } else {
                println!("{} is not valid", id);
            }
        }
    }
}
