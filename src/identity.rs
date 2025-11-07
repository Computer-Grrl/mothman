use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use openmls::prelude::SignatureScheme;
use openmls_traits::signatures::SignerError;
use rand_leg::{RngCore, rngs::OsRng};
use std::{collections::HashMap, num::NonZeroU16};

use crate::{
    error::Error,
    identity::user::{DevicePublicInfo, Persona, ProfilePicture},
};

pub type Ed25519PublicKey = VerifyingKey;
pub type Ed25519Keypair = SigningKey;
pub type Ed25519Signature = Signature;

pub mod device;
pub mod user;

fn generate_secure_random<const SIZE: usize>() -> [u8; SIZE] {
    let mut res = [0; SIZE];
    let mut csprng = OsRng {};

    csprng.fill_bytes(&mut res);

    res
}

pub struct IdentityInfoPackage {
    user_id: [u8; 32],
    user_public_key: Ed25519PublicKey,
    devices: Vec<DevicePublicInfo>,
    default_persona: Persona,
    personas: HashMap<NonZeroU16, Persona>,
    /// Profile picture of the profile
    profile_picture: Option<ProfilePicture>,
    /// timestamp of creation of the package
    created_at: u64,
}

pub struct InfoPackageUploadRequest {
    package_type: InfoPackageType,
    content: InfoPackageContent,
    ttl_seconds: u32,      // 24 hours default
    max_uses: Option<u32>, // Up to 100 scans
}

//TODO: remove InfoPackageType, redundant with InfoPackageContent enum
pub enum InfoPackageType {
    Identity,
}

pub enum InfoPackageContent {
    Identity(IdentityInfoPackage),
}

/// Wrapper for SigningKey
struct Ed25519KeypairWrap<T: ed25519_dalek::Signer<Signature>> {
    pair: T,
}

impl<T: ed25519_dalek::Signer<Signature>> Ed25519KeypairWrap<T> {
    //do not use, panics on fail
    fn _ed25519_sign(&self, payload: &[u8]) -> Vec<u8> {
        self.pair.sign(payload).to_vec()
    }
    //use this instead
    fn ed25519_try_sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.pair.sign(payload).to_vec())
    }
}

//TODO move smoewhere better suited
impl<T: ed25519_dalek::Signer<Signature>> openmls_traits::signatures::Signer
    for Ed25519KeypairWrap<T>
{
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.ed25519_try_sign(payload)
            .map_err(|e| SignerError::SigningError)
            .map(|s| s.to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl<T: ed25519_dalek::Signer<Signature>> From<T> for Ed25519KeypairWrap<T> {
    fn from(value: T) -> Self {
        Ed25519KeypairWrap { pair: value }
    }
}

impl<T: Clone + ed25519_dalek::Signer<Signature>> From<&T> for Ed25519KeypairWrap<T> {
    fn from(value: &T) -> Self {
        Ed25519KeypairWrap {
            pair: value.clone(),
        }
    }
}
