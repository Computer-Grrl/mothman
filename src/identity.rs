use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_leg::{rngs::OsRng, RngCore};
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
