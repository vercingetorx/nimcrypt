# NimCrypt (AEF)

Simple, fast, password‑based file encryption using an authenticated, chunked file format. Supports multiple cipher suites (default XChaCha20‑Poly1305) with strong key derivation via Argon2id. Encrypted filenames are hidden on disk by hashing the encrypted name and appending `.crypt`.

- Multi‑cipher: `xchacha20-poly1305` (default), `aes-gcm-siv`, `twofish-gcm-siv`, `aurora-siv`
- Authenticated chunked format: detects corruption and tampering per chunk
- Password KDF: Argon2id with tunable memory/time/parallelism
- Preserves file metadata (mtime + permissions) on decrypt
- Directory mode: recurse and skip hidden files; ignores existing `.crypt` files
- On success: removes the original file to avoid leaving plaintext behind

## Build

Requires Nim. Example (optimized build):

```
nim c -d:release nimcrypt.nim
```

## Quick Start

- Encrypt a file:
  - `./nimcrypt /path/to/file`
  - Enter the password twice when prompted.
  - Output: a hashed filename ending with `.crypt` (original file is deleted on success).

- Decrypt a file:
  - `./nimcrypt /path/to/file.crypt`
  - Enter the password twice (must match). The `.crypt` file is removed on success.

- Encrypt/decrypt a directory (recursive):
  - Encrypt: `./nimcrypt -r /path/to/dir`
  - Decrypt: `./nimcrypt -d -r /path/to/dir`

Note: If you omit `-e`/`-d`, NimCrypt auto‑detects by extension: files ending in `.crypt` are decrypted; everything else is encrypted.

## Usage

```
nimcrypt [options] <path> [<path> ...]

Modes
  -e, --encrypt      Encrypt (default if not specified)
  -d, --decrypt      Decrypt

General
  -r, --recursive    Recurse into directories
  -q, --quiet        Reduce output
  -v, --version      Print format version

Performance
  --chunk <MiB>      Chunk size in MiB (default: 1)

KDF (Argon2id)
  --m <KiB>          Memory cost in KiB   (default: 65536 = 64 MiB)
  --t <iters>        Time cost (iterations, default: 3)
  --p <lanes>        Parallelism (default: 1)

Cipher suite
  --cipher <name>    xchacha20 | aes-gcm-siv | twofish-gcm-siv | aurora-siv (default: xchacha20)
```

Examples:

- Use AES‑GCM‑SIV and larger chunks (8 MiB):
  - `./nimcrypt --cipher aes-gcm-siv --chunk 8 file.bin`
- Lower Argon2 memory (useful on low‑RAM systems):
  - `./nimcrypt --m 16384 file.bin`  (16 MiB)

## How files are named

- The original filename is encrypted and authenticated.
- The on‑disk name is a BLAKE2s hash of the encrypted filename (keyed) with a `.crypt` suffix, so plaintext names are not exposed.

## What gets preserved

- When decrypting, NimCrypt restores:
  - Modification time (mtime)
  - File permissions (best‑effort on your OS)

## Notes and behavior

- Hidden files are skipped when encrypting directories.
- Existing `.crypt` files are ignored during encryption to avoid double‑encrypting.
- On success, NimCrypt deletes the input file (plaintext when encrypting; `.crypt` when decrypting).
- The format is streaming and chunked; each chunk is independently authenticated.

## Advanced: Format at a glance

- Magic/version: `AEF1` / v3
- KDF: Argon2id (configurable m/t/p) derives a master key; BLAKE2s labels derive per‑file meta/data keys.
- Ciphers: XChaCha20‑Poly1305, AES‑GCM‑SIV, Twofish‑GCM‑SIV, Aurora‑SIV.
- Associated Data (AD): binds header, encrypted filename, optional encrypted metadata, plus chunk index and length.

This design ensures that changing the header, filename, metadata, order of chunks, or any byte in a chunk is detected.

## Security notes

- This project has not been externally audited. Use at your own risk for sensitive data.
- Strong passwords matter. Increase Argon2 parameters (`--m`, `--t`, `--p`) as your machine allows.
- Forgetting the password means the data cannot be recovered.

## Warning

 - [Aurora-PI](https://github.com/vercingetorx/aurora-pi) is an experimental cipher that has not been peer reviewed. It should not be used when you need gueranteed security.
