use rand::Rng;
use rand::rand_core::SeedableRng;
use rand::rngs::OsRng;
use rand_pcg::Pcg64Dxsm;

/// Generate a secure key that can be used as the master decryption key
pub fn generate_key() -> [u8; 64] {
    let mut key = [0u8; 64];

    // todo: attempt to get entropy from OS or TPM

    let mut initial_rng = OsRng;

    let mut srng = Pcg64Dxsm::try_from_rng(&mut initial_rng).unwrap();

    srng.fill(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng() {
        let key = generate_key();
        println!("Key generated: {:?}", key);
    }
}
