# tpm2-rand

This crate provides a simple `rand` generator that uses a TPM2 device to generate random numbers. It implements the `rand_core::RngCore` trait, allowing it to be used seamlessly with the `rand` ecosystem.

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
use tpm2_rand::Tpm2Rand;
use tss_esapi::{
    Context,
    TctiNameConf,
};


let context = Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap();
let mut rng = Tpm2Rand::new(context).unwrap();
let random_bytes = rng.gen::<[u8; 32]>();
println!("Random bytes: {:?}", random_bytes);
```

You should check out [`tss-esapi` documentation](https://docs.rs/tss-esapi/latest/tss_esapi/) for more details on how to set up the TPM2 context and handle errors.

## License

This crate is licensed under either the Apache License, Version 2.0, or the MIT License, at your option. See the [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) files for details.
