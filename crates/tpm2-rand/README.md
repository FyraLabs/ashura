# tpm2-rand

This crate provides a simple `rand` generator that uses a TPM2 device to generate random numbers. It implements the `rand_core::TryRngCore` and `TryCryptoRng` trait, allowing it to be used seamlessly with the `rand` ecosystem.

## Features

It simply exposes the RNG functionality from the TPM2 device, That's it.

## Usage

To use this crate, add the following to your `Cargo.toml`:

```toml
[dependencies]
tpm2-rand = "0"
tss-esapi = "7"
```

Then, you can use it in your code as follows:

```rust
use rand::TryRngCore;
use rand_tpm2::TpmRand;
use tss_esapi::{Context, tcti_ldr::TabrmdConfig};


let mut context = Context::new_with_tabrmd(TabrmdConfig::default())
    .expect("Failed to create Context with Tabrmd");

let mut rng = TpmRand::new(context);
let mut buf = [0u8; 100];


// This will stitch together TPM2 RNG calls to fill the buffer
// even if the TPM can return N (mostly 48) bytes at a time, it will
// keep calling to fill the buffer until it's full.
rng.try_fill_bytes(&mut buf)
    .expect("Failed to get random bytes from TPM");

println!("{:?}", buf);

let len = buf.len();

println!("Length of random bytes: {}", len);

```

You should check out [`tss-esapi` documentation](https://docs.rs/tss-esapi/latest/tss_esapi/) for more details on how to set up the TPM2 context and handle errors.

## License

This crate is licensed under either the Apache License, Version 2.0, or the MIT License, at your option. See the [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) files for details.
