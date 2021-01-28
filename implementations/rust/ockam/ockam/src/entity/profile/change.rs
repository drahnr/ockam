use crate::entity::profile::event_identifier::EventIdentifier;
use crate::entity::profile::proof::ProfileChangeProof;
use crate::entity::profile_change::ProfileChange;

pub type Changes = Vec<ProfileChange>;

#[derive(Clone, Debug)]
pub struct ProfileChangeEvent {
    identifier: EventIdentifier,
    changes: Changes,
    proofs: Vec<ProfileChangeProof>,
}

impl ProfileChangeEvent {
    pub fn identifier(&self) -> &EventIdentifier {
        &self.identifier
    }
    pub fn changes(&self) -> &Changes {
        &self.changes
    }
    pub fn proofs(&self) -> &[ProfileChangeProof] {
        &self.proofs
    }
}

impl ProfileChangeEvent {
    pub fn new(
        identifier: EventIdentifier,
        changes: Changes,
        proofs: Vec<ProfileChangeProof>,
    ) -> Self {
        ProfileChangeEvent {
            identifier,
            changes,
            proofs,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProfileChangeHistory(Vec<ProfileChangeEvent>);

impl ProfileChangeHistory {
    pub fn new(change_events: Vec<ProfileChangeEvent>) -> Self {
        Self(change_events)
    }

    pub fn push_event(&mut self, event: ProfileChangeEvent) {
        self.0.push(event)
    }
}

impl AsRef<[ProfileChangeEvent]> for ProfileChangeHistory {
    fn as_ref(&self) -> &[ProfileChangeEvent] {
        &self.0
    }
}

impl Default for ProfileChangeHistory {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
