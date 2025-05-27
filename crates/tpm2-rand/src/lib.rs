use rand_core::{CryptoRng, RngCore};
use tss_esapi::Context;

pub struct TpmRand {
    tpm_context: Context,
}

impl TpmRand {
    pub fn new(ctx: Context) -> Self {
        Self { tpm_context: ctx }
    }
}

impl RngCore for TpmRand {
    fn next_u32(&mut self) -> u32 {
        let random_bytes = self
            .tpm_context
            .get_random(4)
            .expect("Failed to get random bytes from TPM");
        let buf: [u8; 4] = random_bytes
            .value()
            .try_into()
            .expect("Expected 4 bytes from TPM");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let random_bytes = self
            .tpm_context
            .get_random(8)
            .expect("Failed to get random bytes from TPM");
        let buf: [u8; 8] = random_bytes
            .value()
            .try_into()
            .expect("Expected 8 bytes from TPM");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        const MAX_TPM_RANDOM_BUF: usize = 48;
        let mut offset = 0;
        while offset < dest.len() {
            let chunk_size = core::cmp::min(MAX_TPM_RANDOM_BUF, dest.len() - offset);
            let random_bytes = self
                .tpm_context
                .get_random(chunk_size)
                .expect("Failed to get random bytes from TPM");
            let bytes = random_bytes.value();
            dest[offset..offset + chunk_size].copy_from_slice(&bytes[..chunk_size]);
            offset += chunk_size;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TpmRand {}

#[cfg(test)]
mod tests {
    use super::*;
    use tss_esapi::{TctiNameConf, tcti_ldr::TabrmdConfig};

    #[test]
    fn test_tpm_rand() {
        let tcti = TctiNameConf::Tabrmd(TabrmdConfig::default());
        let ctx = Context::new(tcti).unwrap();
        let mut rng = TpmRand::new(ctx);

        let mut buf = [0u8; 128];
        rng.fill_bytes(&mut buf);
        assert!(!buf.is_empty(), "Buffer should not be empty");

        println!("Random bytes: {:?}", buf);
    }
}
