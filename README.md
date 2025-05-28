# Ashura

Ashura is a secure, TPM-backed secret storage library powered by [sled], [secrecy], and [bincode].

It provides a straightforward and efficient approach to managing secrets with hardware-enforced protection. By leveraging the Trusted Platform Module (TPM), Ashura ensures that sensitive data remains inaccessible without proper device-bound authorization.

> [!NOTE]
> 🚧 Ashura is under active development and not yet ready for production use. Planned features include a [Freedesktop Secret Service](https://specifications.freedesktop.org/secret-service/) frontend, enabling drop-in compatibility with existing Linux desktop applications.

## How it works

Ashura securely generates a master AES encryption key using the TPM's hardware RNG. This key is immediately **sealed** using the TPM — binding its use to the device and optionally to its platform state (PCRs). Once sealed, the original master key is erased from memory and can only be recovered by the TPM itself.

When encrypting or decrypting secrets:

1. The sealed master key is **unsealed** by the TPM.
2. A **session key** is derived from the master key using [HKDF](https://en.wikipedia.org/wiki/HKDF).
3. The session key is used for secret encryption/decryption.
4. The master key is **discarded immediately** after use.

To enhance security, additional inputs (e.g., a user-provided password, salt, or context info) may be included in the HKDF process. This enables per-secret key derivation while still keeping the sealed master key as the trust root.

### Diagram

```text
+-----------+   Generates    +----------------+   Seals with   +-------------------+
|   TPM     |--------------->| Master AES Key |--------------->|  TPM Sealed Key   |
|  (RNG)    |                +----------------+                +-------------------+
+-----------+                     |                                        |
                                  | (Immediately Forgotten)                V
                                  |                               +-------------------+
                                  +------------------------------>| Sealed Master Key |
                                                                  | (Stored)          |
                                                                  +-------------------+
                                                                         |
                                                                         | (TPM unseals/uses
                                                                         |  Master Key for HKDF)
                                                                         V
+-----------------------+  Optional  +---------------------+   Derives    +---------------+   Uses to     +-----------+
| Additional Inputs     |----------->|        HKDF         |<-------------| Session Key   |<------------->| Secrets   |
| (Salt, Password, etc.)|  Inputs    | (from Master Key)   |              +---------------+ (Encrypt/Decrypt) +-----------+
+-----------------------+            +---------------------+
```

## Requirements

- A Trusted Platform Module (TPM) 2.0 compliant device with `EncryptDecrypt2` and AES-128-CFB support. (Support for RSA is incomplete, planned)
- A Linux environment with the `tpm2-tss` libraries installed.
- UEFI boot to allow TPM access.
- Somewhere on the disk to store the encrypted secrets database (e.g., `~/.local/share/ashura`).

## Contributing

Ashura is currently in an early planning and development phase. We welcome suggestions and contributions to help shape its architecture and processes, as these are still evolving and not yet finalized. Your input is highly valued. We also encourage contributions to the codebase, documentation, and testing. Feel free to open an issue to discuss ideas or submit a pull request.


[sled]: https://docs.rs/sled/
[secrecy]: https://docs.rs/secrecy/
[bincode]: https://docs.rs/bincode/