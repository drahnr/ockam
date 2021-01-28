use crate::software_vault::SoftwareVault;
use ockam_core::Error;
use ockam_vault_core::kid_vault::KidVault;
use ockam_vault_core::secret::Secret;

impl KidVault for SoftwareVault {
    fn get_secret_by_kid(&self, kid: &str) -> Result<Secret, Error> {
        let index = self
            .entries
            .iter()
            .find(|(_, entry)| {
                if let Some(e_kid) = entry.kid() {
                    e_kid == kid
                } else {
                    false
                }
            })
            .unwrap()
            .0; //FIXME

        Ok(Secret::new(index.clone()))
    }
}
