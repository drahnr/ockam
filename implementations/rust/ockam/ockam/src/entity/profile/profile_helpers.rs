// FIXME: Give me better name, pls

use crate::entity::profile::event_identifier::EventIdentifier;
use crate::entity::profile::profile_change::ProfileChange;
use crate::entity::profile::profile_change_type::ProfileChangeType::{CreateKey, RotateKey};
use crate::entity::profile::proof::{ProfileChangeProof, Signature, SignatureType};
use crate::entity::{KeyAttributes, Profile, ProfileChangeEvent};
use crate::OckamError;
use ockam_vault_core::secret::Secret;

impl Profile {
    pub(crate) fn get_last_event_id(&self) -> Result<EventIdentifier, ockam_core::Error> {
        if let Some(e) = self.change_history.as_ref().last() {
            Ok(e.identifier().clone())
        } else {
            Err(OckamError::InvalidInternalState.into())
        }
    }

    pub(crate) fn find_key_change_in_event<'a>(
        event: &'a ProfileChangeEvent,
        key_attributes: &KeyAttributes,
    ) -> Option<&'a ProfileChange> {
        event
            .changes()
            .iter()
            .rev()
            .find(|c| match c.change_type() {
                CreateKey(change) => change.key_attributes() == key_attributes,
                RotateKey(change) => change.key_attributes() == key_attributes, // RevokeKey(event) => {
                                                                                //     event.key_type() == key_type && event.key_purpose() == key_purpose && event.label() == label
                                                                                // }
            })
    }

    pub(crate) fn find_last_key_event(
        &self,
        key_attributes: &KeyAttributes,
    ) -> Result<&ProfileChangeEvent, ockam_core::Error> {
        self.change_history
            .as_ref()
            .iter()
            .rev()
            .find(|e| Self::find_key_change_in_event(e, key_attributes).is_some())
            .ok_or(OckamError::InvalidInternalState.into())
    }

    pub(crate) fn find_key_event_before(
        &self,
        event_id: &EventIdentifier,
        key_attributes: &KeyAttributes,
    ) -> Result<&ProfileChangeEvent, ockam_core::Error> {
        let before_index = self
            .change_history
            .as_ref()
            .iter()
            .position(|e| e.identifier() == event_id)
            .unwrap_or(self.change_history.as_ref().len());
        self.change_history.as_ref()[..before_index]
            .iter()
            .rev()
            .find(|e| Self::find_key_change_in_event(e, key_attributes).is_some())
            .ok_or(OckamError::InvalidInternalState.into())
    }

    pub(crate) fn get_change_public_key(
        change: &ProfileChange,
    ) -> Result<&[u8], ockam_core::Error> {
        match change.change_type() {
            CreateKey(change) => Ok(change.public_key()),
            RotateKey(change) => Ok(change.public_key()),
        }
    }

    pub(crate) fn get_private_key_from_event(
        &self,
        key_attributes: &KeyAttributes,
        event: &ProfileChangeEvent,
    ) -> Result<Secret, ockam_core::Error> {
        let change = Self::find_key_change_in_event(event, key_attributes).unwrap(); // FIXME

        let public_key = Self::get_change_public_key(change).unwrap(); // FIXME
        let vault = self.vault.lock().unwrap();

        let public_kid = vault.sha256(public_key)?;
        let public_kid = hex::encode(&public_kid);

        vault.get_secret_by_kid(&public_kid)
    }

    fn get_signature(
        change_event: &ProfileChangeEvent,
        signature_type: SignatureType,
    ) -> Result<&Signature, ockam_core::Error> {
        let signatures: Vec<&Signature> = change_event
            .proofs()
            .iter()
            .filter_map(|p| match p {
                ProfileChangeProof::Signature(s) => {
                    if *s.stype() == signature_type {
                        Some(s)
                    } else {
                        None
                    }
                }
            })
            .collect();

        if signatures.len() != 1 {
            return Err(OckamError::InvalidProof.into());
        }

        Ok(signatures.first().unwrap()) // FIXME
    }

    pub(crate) fn get_self_signature(
        change_event: &ProfileChangeEvent,
    ) -> Result<&Signature, ockam_core::Error> {
        Self::get_signature(change_event, SignatureType::SelfSign)
    }

    pub(crate) fn get_prev_signature(
        change_event: &ProfileChangeEvent,
    ) -> Result<&Signature, ockam_core::Error> {
        Self::get_signature(change_event, SignatureType::Previous)
    }
}
