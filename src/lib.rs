use openmls::prelude::Ciphersuite;

pub mod error;
pub mod identity;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
