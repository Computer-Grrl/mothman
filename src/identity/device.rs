use crate::identity::Ed25519Keypair;

/// Device-level identity (MLS Layer)
/// Each device has its own keypair, even within the same user identity
pub struct DeviceIdentity {
    // Core cryptographic identity (permanent, MLS layer only)
    device_id: [u8; 32],
    // Device keypair used exclisively for MLS operations
    keypair: Ed25519Keypair,
    // Delivery addresses (ephemeral, rotatable)
    delivery_addresses: Vec<DeliveryAddress>,
    // Unix timestamp of creation
    created_timestamp: u64,
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
