use rand_core::{TryCryptoRng, TryRngCore};
use tss_esapi::Context;

pub struct TpmRand {
    tpm_context: Context,
}

impl TpmRand {
    pub fn new(ctx: Context) -> Self {
        Self { tpm_context: ctx }
    }
}

impl TryRngCore for TpmRand {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let random_bytes = self
            .tpm_context
            .get_random(4)
            .map_err(|e| Box::new(e) as Self::Error)?;
        let buf: [u8; 4] = random_bytes
            .value()
            .try_into()
            .map_err(|_| "Expected 4 bytes from TPM")?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let random_bytes = self
            .tpm_context
            .get_random(8)
            .map_err(|e| Box::new(e) as Self::Error)?;
        let buf: [u8; 8] = random_bytes
            .value()
            .try_into()
            .map_err(|_| "Expected 8 bytes from TPM")?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        tracing::trace!("Filling {} bytes from TPM", dest.len());
        let mut offset = 0;
        while offset < dest.len() {
            let remaining = dest.len() - offset;
            tracing::trace!(
                "Requesting {} bytes from TPM, offset: {}",
                remaining,
                offset
            );
            let random_bytes = self
                .tpm_context
                .get_random(remaining)
                .map_err(|e| Box::new(e) as Self::Error)?;
            let bytes = random_bytes.value();
            let n = bytes.len().min(remaining);
            tracing::trace!("TPM returned {} bytes", n);
            if n == 0 {
                tracing::error!("TPM returned zero random bytes");
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TPM returned zero random bytes",
                )));
            }
            dest[offset..offset + n].copy_from_slice(&bytes[..n]);
            offset += n;
        }
        tracing::trace!("Successfully filled {} bytes from TPM", dest.len());
        Ok(())
    }
}

impl TryCryptoRng for TpmRand {}

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
        rng.try_fill_bytes(&mut buf).expect("Failed to fill bytes");
        assert!(!buf.is_empty(), "Buffer should not be empty");

        println!("Random bytes: {:?}", buf);
    }
}
