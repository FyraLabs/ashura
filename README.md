# Ashura

Ashura is a secure, (optionally) TPM-backed secrets manager powered by [sled], [secrecy], and [bincode].

> [!NOTE]
> 🚧 Ashura is under active development and not yet ready for production use. Planned features include a [Freedesktop Secret Service](https://specifications.freedesktop.org/secret-service/) frontend, enabling drop-in compatibility with existing Linux desktop applications.

## How it works

Ashura relies on the concept of _keyslots_ similar to LUKS.

Ashura creates a _master key_ for each keyring, which is then encrypted using a keyslot and immediately forgotten.

For subsequent unlocks this key must then be recovered by decrypting the ciphertext using one of the allowed keyslot methods.

## Requirements

- A Trusted Platform Module (TPM) 2.0 compliant device with `EncryptDecrypt2` and AES-128-CFB support. (Support for RSA is incomplete, planned)
- A Linux environment with the `tpm2-tss` libraries installed.
- UEFI boot to allow TPM access.
- Somewhere on the disk to store the encrypted secrets database (e.g., `~/.local/share/ashura`).
