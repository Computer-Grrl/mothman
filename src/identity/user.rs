use ed25519_dalek::{Signer};
use rand_leg::rngs::OsRng;

use crate::identity::device::DeliveryAddress;

use super::*;

/// Data structure for user identity
pub struct UserId {
    /// id of the user
    id: [u8; 32],
    /// cryptographic signing data
    keypair: Ed25519Keypair,
    /// list of associated devices
    devices: Vec<DevicePublicInfo>,
    /// user's default persona
    default_persona: Persona,
    /// user's other personas
    personas: HashMap<NonZeroU16, Persona>,
}

/// information of devices that's publicly accessible
#[derive(Debug, Clone)]
pub struct DevicePublicInfo {
    // The device's ID
    device_id: [u8; 32],
    /// public key
    public_key: Ed25519PublicKey,
    /// Initial contact adress
    initial_delivery_address: DeliveryAddress,
    /// Host server for the keypackages
    keypackage_server: String,
    // Timestamp of linking time
    linked_at: u64,
}

#[derive(Debug, Clone)]
pub struct ProfilePicture {
    /// mime type of the image e.g., "image/png"
    mime_type: String,
    /// Raw image data or hash/link if large
    data: Vec<u8>,
    /// Timestamp
    uploaded_at: u64,
    /// Signed for authenticity
    signature: Ed25519Signature,
}

/// public display information for the account
#[derive(Debug, Clone)]
pub struct Persona {
    /// Name to display for this persona
    display_name: String,
    /// Optional profile picture to display for this persona
    profile_picture: Option<ProfilePicture>,
    /// Biography to display for this persona
    bio: Option<String>,
    /// Pronouns to display for this persona
    pronouns: Option<String>,
}

/// Enum for persona identifiers
pub enum PersonaId {
    /// this persona is the default persona
    Default,
    /// this persona has a non-zero ID
    Id(NonZeroU16),
}

/// User Identity
impl UserId {
    /// Generate a new user identity.
    ///
    /// Should only ever happen once, on first device setup.
    pub fn generate() -> Self {
        let mut csprng = OsRng {};
        UserId {
            id: generate_secure_random::<32>(),
            keypair: Ed25519Keypair::generate(&mut csprng),
            devices: Vec::new(),
            default_persona: Persona {
                display_name: "My Name".to_string(),
                profile_picture: None,
                bio: None,
                pronouns: None,
            },
            personas: HashMap::new(),
        }
    }

    /// Add a persona
    fn add_persona(&mut self, persona: Persona) -> Result<NonZeroU16, Error> {
        // Find next available key
        let next_key = NonZeroU16::new(
            (1..u16::MAX)
                .find(|k| !self.personas.contains_key(&NonZeroU16::new(*k).unwrap()))
                .ok_or(Error::PersonasFull)?,
        )
        .unwrap();
        self.personas.insert(next_key, persona);

        Ok(next_key)
    }

    /// Finds the persona with the given ID
    pub fn persona_for(&self, id: PersonaId) -> Option<&Persona> {
        match id {
            PersonaId::Default => Some(&self.default_persona),
            PersonaId::Id(id) => self.personas.get(&id),
        }
    }

    /// Gets the default persona
    pub fn default_persona(&self) -> &Persona {
        &self.default_persona
    }

    /// Removes a persona
    pub fn remove_persona(&mut self, id: NonZeroU16) -> Result<Persona, Error> {
        self.personas.remove(&id).ok_or(Error::PersonaNotFound)
    }

    /// Create the information package with the default profile picture
    fn create_info_package(&self) -> InfoPackageUploadRequest {
        self.create_info_package_with_pfp(self.default_persona.profile_picture.clone())
    }

    /// Create the information package with a specific profile picture
    fn create_info_package_with_pfp(
        &self,
        pfp: Option<ProfilePicture>,
    ) -> InfoPackageUploadRequest {
        // Create identity package content
        let identity_package = IdentityInfoPackage {
            user_id: self.id,
            user_public_key: self.keypair.verifying_key(),
            devices: self.devices.clone(),
            default_persona: self.default_persona.clone(),
            personas: self.personas.clone(),
            profile_picture: pfp,
            created_at: time::UtcDateTime::now().unix_timestamp() as u64,
        };

        // Prepare upload request with TTL and usage limits
        InfoPackageUploadRequest {
            package_type: InfoPackageType::Identity,
            content: InfoPackageContent::Identity(identity_package),
            ttl_seconds: 24 * 3600, // 24 hours default
            max_uses: Some(100),    // Up to 100 scans
        }
    }

    /// Sign data with user identity key
    fn sign(&self, data: &[u8]) -> Result<Ed25519Signature, Error> {
        self.keypair
            .try_sign(data)
            .map_err(|e| Error::SigningError(e))
    }

    /// Add a linked device to this user account
    fn add_linked_device(&mut self, device_info: DevicePublicInfo) {
        self.devices.push(device_info);
    }

    /// Remove a device
    fn remove_device(&mut self, deviceid: &[u8; 32]) {
        self.devices.retain(|d| &d.device_id != deviceid);
    }
}
