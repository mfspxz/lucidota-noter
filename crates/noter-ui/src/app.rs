use crate::{NoteSummary, NoteView, SearchHit, SyncReport};
use noter_crypto::{derive_master_key, derive_subkey, DeviceIdentity, PublicIdentity, Salt, SecretBytes};
use noter_mesh::Session;
use noter_model::{Note, Notes};
use noter_search::SearchIndex;
use noter_store::{now_ms, Store, StoreError};
use noter_sync::{MergeOutcome, SyncEngine};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("crypto: {0}")]
    Crypto(#[from] noter_crypto::CryptoError),
    #[error("sync: {0}")]
    Sync(#[from] noter_sync::SyncError),
    #[error("mesh: {0}")]
    Mesh(#[from] noter_mesh::MeshError),
    #[error("airgap: {0}")]
    Airgap(#[from] noter_airgap::AirgapError),
    #[error("search: {0}")]
    Search(#[from] noter_search::SearchError),
    #[error("share: {0}")]
    Share(#[from] noter_share::ShareError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// The unlocked vault. Owns everything the UI needs.
pub struct App {
    store: Store,
    master: SecretBytes,
    device_id: String,
    identity: DeviceIdentity,
}

impl App {
    /// Open (or create) the vault at `db_path`, deriving the master key
    /// from the passphrase via Argon2id.
    pub fn unlock(db_path: &Path, passphrase: &str, salt: &Salt) -> Result<Self, AppError> {
        let master = derive_master_key(passphrase, salt)?;
        Self::open_with_master(db_path, master)
    }

    /// Open with an already-derived master key (tests / alternate unlock).
    pub fn open_with_master(db_path: &Path, master: SecretBytes) -> Result<Self, AppError> {
        let store = Store::open(db_path, &master)?;
        // Deterministic device identity from the master key: same passphrase
        // on a fresh install recovers the same device identity.
        let id_sub = derive_subkey(&master, b"noter/device-id/v1");
        let h = blake3::hash(id_sub.as_bytes());
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&id_sub.as_bytes()[..32]);
        seed[32..].copy_from_slice(&h.as_bytes()[..32]);
        let identity = DeviceIdentity::from_seed_bytes(&seed)?;
        let device_id = format!(
            "dev-{}",
            master.as_bytes()[..2].iter().map(|b| format!("{:02x}", b)).collect::<String>()
        );
        Ok(Self {
            store,
            master,
            device_id,
            identity,
        })
    }

    pub(crate) fn engine(&self) -> SyncEngine<'_> {
        let seed = self.identity.export_seed();
        SyncEngine::new(
            &self.device_id,
            DeviceIdentity::import_seed(&seed).expect("seed roundtrips"),
            self.master.clone(),
            &self.store,
        )
    }

    pub(crate) fn notes(&self) -> Notes<'_> {
        Notes::new(&self.store)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn public_identity(&self) -> PublicIdentity {
        self.identity.public()
    }

    pub fn master(&self) -> &SecretBytes {
        &self.master
    }

    pub fn store(&self) -> &Store {
        &self.store
    }
}
