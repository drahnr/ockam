use crate::entity::profile::event_identifier::EventIdentifier;
use crate::entity::profile::profile_change::ProfileChange;
use crate::entity::profile::profile_change_type::ProfileChangeType;
use crate::entity::profile::proof::{ProfileChangeProof, Signature, SignatureType};
use crate::entity::{
    KeyAttributes, Profile, ProfileChangeEvent, ProfileEventAttributes, ProfileVault,
};
use crate::OckamError;
use ockam_vault_core::types::{SecretAttributes, SecretPersistence, SecretType};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateKeyChange {
    key_attributes: KeyAttributes,
    public_key: Vec<u8>,
}

impl CreateKeyChange {
    pub fn key_attributes(&self) -> &KeyAttributes {
        &self.key_attributes
    }
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }
}

impl CreateKeyChange {
    pub fn new(key_attributes: KeyAttributes, public_key: Vec<u8>) -> Self {
        CreateKeyChange {
            key_attributes,
            public_key,
        }
    }
}

impl Profile {
    pub(crate) fn create_key_event_static(
        prev_id: EventIdentifier,
        key_attributes: KeyAttributes,
        attributes: Option<ProfileEventAttributes>,
        vault: Arc<Mutex<dyn ProfileVault>>,
    ) -> Result<ProfileChangeEvent, ockam_core::Error> {
        let attributes = attributes.unwrap_or(ProfileEventAttributes::new());

        let mut v = vault.lock().unwrap();

        // TODO: Should be customisable
        let secret_attributes = SecretAttributes {
            stype: SecretType::Curve25519,
            persistence: SecretPersistence::Persistent,
            length: 0,
        };

        let private_key = v.secret_generate(secret_attributes)?;
        let public_key = v.secret_public_key_get(&private_key)?;

        let change = CreateKeyChange::new(key_attributes, public_key.as_ref().to_vec());
        let profile_change =
            ProfileChange::new(1, prev_id, attributes, ProfileChangeType::CreateKey(change));
        let changes = vec![profile_change];
        let changes_binary =
            serde_bare::to_vec(&changes).map_err(|_| OckamError::BareError.into())?;

        let event_id = v.sha256(&changes_binary)?;
        let event_id = EventIdentifier::from_hash(event_id);

        let self_signature = v.sign(&private_key, event_id.as_ref())?;
        let self_signature =
            ProfileChangeProof::Signature(Signature::new(SignatureType::SelfSign, self_signature));

        let signed_change_event = ProfileChangeEvent::new(event_id, changes, vec![self_signature]);

        Ok(signed_change_event)
    }

    pub(crate) fn create_key_event(
        &mut self,
        key_attributes: KeyAttributes,
        attributes: Option<ProfileEventAttributes>,
    ) -> Result<ProfileChangeEvent, ockam_core::Error> {
        // Creating key after it was revoked is forbidden
        if self.find_last_key_event(&key_attributes).is_ok() {
            return Err(OckamError::InvalidInternalState.into());
        }

        let prev_id = self.get_last_event_id()?;

        Self::create_key_event_static(prev_id, key_attributes, attributes, self.vault.clone())
    }
}
