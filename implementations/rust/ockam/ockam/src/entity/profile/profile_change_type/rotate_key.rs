use crate::entity::profile::event_identifier::EventIdentifier;
use crate::entity::profile::profile_change::ProfileChange;
use crate::entity::profile::profile_change_type::ProfileChangeType;
use crate::entity::profile::proof::{ProfileChangeProof, Signature, SignatureType};
use crate::entity::{KeyAttributes, Profile, ProfileChangeEvent, ProfileEventAttributes};
use crate::OckamError;
use ockam_vault_core::types::{SecretAttributes, SecretPersistence, SecretType};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateKeyChange {
    key_attributes: KeyAttributes,
    public_key: Vec<u8>,
}

impl RotateKeyChange {
    pub fn key_attributes(&self) -> &KeyAttributes {
        &self.key_attributes
    }
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }
}

impl RotateKeyChange {
    pub fn new(key_attributes: KeyAttributes, public_key: Vec<u8>) -> Self {
        RotateKeyChange {
            key_attributes,
            public_key,
        }
    }
}

impl Profile {
    pub(crate) fn rotate_key_event(
        &self,
        key_attributes: KeyAttributes,
        attributes: Option<ProfileEventAttributes>,
    ) -> Result<ProfileChangeEvent, ockam_core::Error> {
        let attributes = attributes.unwrap_or(ProfileEventAttributes::new());

        let prev_event_id = self.get_last_event_id()?;

        let last_event_in_chain = self.find_last_key_event(&key_attributes)?;

        let last_key_in_chain =
            self.get_private_key_from_event(&key_attributes, last_event_in_chain)?;

        let mut v = self.vault.lock().unwrap();

        // TODO: Should be customisable
        let secret_attributes = SecretAttributes {
            stype: SecretType::Curve25519,
            persistence: SecretPersistence::Persistent,
            length: 0,
        };

        let private_key = v.secret_generate(secret_attributes)?;
        let public_key = v.secret_public_key_get(&private_key)?.as_ref().to_vec();

        let event = RotateKeyChange::new(key_attributes, public_key);

        let change = ProfileChange::new(
            1,
            prev_event_id,
            attributes.clone(),
            ProfileChangeType::RotateKey(event),
        );
        let changes = vec![change];
        let changes_binary =
            serde_bare::to_vec(&changes).map_err(|_| OckamError::BareError.into())?;

        let event_id = v.sha256(&changes_binary)?;
        let event_id = EventIdentifier::from_hash(event_id);

        let self_signature = v.sign(&private_key, event_id.as_ref())?;
        let self_signature =
            ProfileChangeProof::Signature(Signature::new(SignatureType::SelfSign, self_signature));

        let prev_signature = v.sign(&last_key_in_chain, event_id.as_ref())?;
        let prev_signature =
            ProfileChangeProof::Signature(Signature::new(SignatureType::Previous, prev_signature));

        let signed_change_event =
            ProfileChangeEvent::new(event_id, changes, vec![self_signature, prev_signature]);

        Ok(signed_change_event)
    }
}
