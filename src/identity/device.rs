use ed25519_dalek::Signer;
use openmls::prelude::{
    CredentialWithKey, HpkeKeyPair, HpkePrivateKey, KeyPackage, KeyPackageBundle, SecretVLBytes,
    SignaturePublicKey,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use rand_leg::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::{
    CIPHERSUITE,
    error::Error,
    identity::{Ed25519Keypair, Ed25519KeypairWrap, Ed25519Signature},
    mls::MLSCredential,
};

/// Device-level identity (MLS Layer)
/// Each device has its own keypair, even within the same user identity
pub struct DeviceId {
    /// Device identity
    device_id: [u8; 32],
    /// Device keypair used for MLS operations
    keypair: Ed25519Keypair,
    /// Delivery addresses
    delivery_addresses: Vec<DeliveryAddress>,
    /// Unix timestamp of creation
    created_timestamp: u64,
    /// Display name of the device
    display_name: Option<String>,
}

/// address to deliver to
#[derive(Debug, Clone)]
pub struct DeliveryAddress {
    // Address identifier (e.g., "a1b2c3d4e5...")
    prefix: String,
    // Server domain (e.g., "chat.example.com")
    server: String,
    // Timestamp of when the address was generated
    created_at: u64,
    // Can be deactivated without deletion
    active: bool,
}

impl DeliveryAddress {
    fn full_address(&self) -> String {
        format!("{}@{}", self.prefix, self.server)
    }
}

impl DeviceId {
    /// Generate a new device identity without any external dependencies
    fn generate() -> Self {
        let mut csprng = OsRng {};
        let keypair = Ed25519Keypair::generate(&mut csprng);
        let hash: [u8; 32] = Sha256::digest(keypair.verifying_key().as_bytes()).into();
        Self {
            // Modern elliptic curve cryptography
            keypair: keypair,
            // Derive device_id from public key
            device_id: hash,
            created_timestamp: time::UtcDateTime::now().unix_timestamp() as u64,
            // User can set this later, e.g., "Alice's Phone"
            display_name: None,
            // Initially create empty delivery addresses
            delivery_addresses: Vec::new(),
        }
    }

    /// Sign data with device's identity key
    fn sign(&self, data: &[u8]) -> Result<Ed25519Signature, Error> {
        self.keypair
            .try_sign(data)
            .map_err(|e| Error::SigningError(e))
    }

    /// Create MLS credential for group operations
    pub(crate) fn create_mls_credential(&self) -> CredentialWithKey {
        todo!()
    }

    /// Create a new delivery address for the device
    fn create_delivery_address(&mut self, server: &str) -> String {
        // Generate random 16-byte identifier
        let mut random: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut random);
        let prefix = hex::encode(random);

        let addr = DeliveryAddress {
            prefix: prefix.clone(),
            server: server.to_string(),
            created_at: time::UtcDateTime::now().unix_timestamp() as u64,
            active: true,
        };

        self.delivery_addresses.push(addr);

        // Return full address
        format!("{}@{}", prefix, server)
    }

    /// Deactivate a delivery address
    fn burn_address(&mut self, full_address: &str) {
        if let Some(addr) = self
            .delivery_addresses
            .iter_mut()
            .find(|a| a.full_address() == full_address)
        {
            addr.active = false;
        }
    }

    /// Get all active delivery addresses
    fn active_addresses(&self) -> Vec<String> {
        self.delivery_addresses
            .iter()
            .filter(|a| a.active)
            .map(|a| a.full_address())
            .collect()
    }

    /// Get all active addresses for a specific server
    fn active_addresses_for_server(&self, server: &str) -> Vec<String> {
        self.delivery_addresses
            .iter()
            .filter(|a| a.active && a.server == server)
            .map(|a| a.full_address())
            .collect()
    }

    /// Verify device_id is correctly derived from public key
    fn verify_device_id(&self) -> bool {
        let expected: [u8; 32] = Sha256::digest(self.keypair.verifying_key().as_bytes()).into();
        self.device_id == expected
    }

    fn generate_key_packages(&self, count: usize) -> Vec<KeyPackageBundle> {
        // Implementation note: Uses MLS RFC 9420 KeyPackage format
        // with cipher suite MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

        (0..count)
            .map(|_| {
                // OpenMLS implementation
                KeyPackage::builder()
                    .build(
                        CIPHERSUITE,
                        &OpenMlsRustCrypto::default(),
                        &Ed25519KeypairWrap::from(&self.keypair),
                        self.create_mls_credential(),
                    )
                    .unwrap()

                // Returns KeyPackageBundle with:
                // - key_package: Public part (uploaded to server)
                // - private_key: Secret part (stored locally for welcome decryption)
            })
            .collect()
    }
}
