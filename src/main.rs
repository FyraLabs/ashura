use rand::TryRngCore;
use rand_tpm2::TpmRand;
use tracing::Level;
use tss_esapi::{Context, tcti_ldr::TabrmdConfig};
fn main() {
    let mut context = Context::new_with_tabrmd(TabrmdConfig::default())
        .expect("Failed to create Context with Tabrmd");

    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .init();
    tracing::trace!("meow");
    let mut rng = TpmRand::new(context);
    // loop {
    let mut buf = [0u8; 100];

    rng.try_fill_bytes(&mut buf)
        .expect("Failed to get random bytes from TPM");
    println!("{:?}", buf);
    let len = buf.len();
    println!("Length of random bytes: {}", len);
    // }
}
