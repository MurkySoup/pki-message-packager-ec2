# pki-message-packager-ec2

ECC PKI Message Packager - ECI2 (X25519 + ML-KEM-768 + HKDF-SHA-384 + AES-256-GCM)

---

## Description

A command-line utility for securely packaging arbitrary message data using modern elliptic-curve cryptography using a hybrid classical/post-quantum public-key encryption construction.

ECI2 version combines:

* **X25519** — classical elliptic-curve key agreement
* **ML-KEM-768** — NIST-standardized post-quantum key encapsulation mechanism
* **HKDF-SHA-384** — key derivation and hybrid-secret combination
* **AES-256-GCM** — authenticated symmetric encryption

The design is intended to provide confidentiality against both conventional attackers and future attackers capable of breaking X25519 with a sufficiently capable quantum computer.

> **Status:** Experimental / application-specific protocol
>
> ECI2 is not an established interoperable encryption standard. It is an implementation of a deliberately specified application-level hybrid encryption protocol. Do not assume interoperability with other ECIES, X25519, or ML-KEM implementations.

---

## Features

* Hybrid **X25519 + ML-KEM-768** key establishment.
* AES-256-GCM authenticated encryption.
* HKDF-SHA-384 hybrid key derivation.
* Explicit protocol and cryptographic-suite identifiers.
* Authenticated package headers using AES-GCM AAD.
* Strict binary package validation.
* Separate ECI2 public/private key containers.
* Optional Base64 package encoding.
* Command-line operation suitable for shell pipelines.
* Approximately 1 GiB maximum message size.
* Python 3.11+.
* Uses the `cryptography` package for all cryptographic primitives.
* Does not implement cryptographic primitives itself.

---

# Security Overview

## Why hybrid encryption?

A conventional construction such as:

```text
X25519
   |
   v
HKDF
   |
   v
AES-256-GCM
```

is vulnerable to a sufficiently capable quantum computer because Shor's algorithm can theoretically recover the X25519 private key.

AES-256 and HKDF do not compensate for that weakness.

ECI2 therefore combines two independent key-establishment mechanisms:

```text
                 Recipient Public Key
                         |
              +----------+----------+
              |                     |
           X25519                ML-KEM-768
              |                     |
              |                encapsulation
              |                     |
              +----------+----------+
                         |
                Two shared secrets
                         |
                         v
                   HKDF-SHA-384
                         |
                         v
                    AES-256 key
                         |
                         v
                    AES-256-GCM
```

The AES encryption key is derived from **both** the X25519 and ML-KEM shared secrets.

Consequently, compromise of X25519 alone does not reveal the AES encryption key.

---

# Cryptographic Suite

ECI2 currently defines one cryptographic suite:

| Function                | Algorithm    |
| ----------------------- | ------------ |
| Classical key agreement | X25519       |
| Post-quantum KEM        | ML-KEM-768   |
| KDF                     | HKDF-SHA-384 |
| Symmetric encryption    | AES-256-GCM  |
| AES key size            | 256 bits     |
| GCM nonce               | 96 bits      |
| HKDF salt               | 256 bits     |
| ML-KEM parameter set    | ML-KEM-768   |

The suite identifier is:

```text
1
```

The protocol deliberately identifies the suite in every key container and every encrypted package.

This permits future protocol versions to introduce additional cryptographic suites without silently changing the meaning of existing packages.

---

# Requirements

* Python **3.11 or newer**
* `cryptography >= 47.0,<52`

Install dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

A virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

The ML-KEM implementation is provided by `cryptography`; ECI2 does not implement ML-KEM itself.

---

# Installation

Clone the repository:

```bash
git clone <repository-url>
cd <repository-directory>
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Verify the installation:

```bash
python3 pki-message-packager-eci2.py --version
```

Example:

```text
ECI2 1.0; cryptography 50.0.2
```

---

# Key Generation

Generate an ECI2 recipient keypair:

```bash
python3 pki-message-packager-eci2.py keygen \
    --private recipient.eci2.private \
    --public recipient.eci2.public
```

The result is two files:

```text
recipient.eci2.private
recipient.eci2.public
```

The private key contains:

* X25519 private key
* ML-KEM-768 private seed

The public key contains:

* X25519 public key
* ML-KEM-768 public key

The private key is written with restrictive file permissions where supported.

### Overwriting an existing key

The utility will not overwrite existing key files by default.

Use:

```bash
python3 pki-message-packager-eci2.py keygen \
    --private recipient.eci2.private \
    --public recipient.eci2.public \
    --force
```

Use `--force` carefully. Existing keys should normally be preserved for decrypting previously encrypted material.

---

# Encrypting a Message

Encrypt a short text message:

```bash
python3 pki-message-packager-eci2.py encrypt \
    --key recipient.eci2.public \
    --message 'Hello from ECI2.' \
    --output message.eci2
```

The resulting file contains the ECI2 binary package.

---

# Decrypting a Message

Decrypt the package:

```bash
python3 pki-message-packager-eci2.py decrypt \
    --key recipient.eci2.private \
    --input message.eci2
```

The plaintext is written to stdout.

To save it:

```bash
python3 pki-message-packager-eci2.py decrypt \
    --key recipient.eci2.private \
    --input message.eci2 \
    --output message.txt
```

---

# Encrypting Files

Encrypt a file:

```bash
python3 pki-message-packager-eci2.py encrypt \
    --key recipient.eci2.public \
    --input document.pdf \
    --output document.pdf.eci2
```

Decrypt it:

```bash
python3 pki-message-packager-eci2.py decrypt \
    --key recipient.eci2.private \
    --input document.pdf.eci2 \
    --output document.pdf
```

The decrypted file should be byte-for-byte identical to the original.

---

# Base64 Encoding

ECI2 normally produces binary output.

For systems that require text-safe transport, use `--base64`:

```bash
python3 pki-message-packager-eci2.py encrypt \
    --key recipient.eci2.public \
    --input document.pdf \
    --base64 \
    --output document.pdf.eci2.b64
```

Decrypt:

```bash
python3 pki-message-packager-eci2.py decrypt \
    --key recipient.eci2.private \
    --input document.pdf.eci2.b64 \
    --base64 \
    --output document.pdf
```

Base64 provides encoding only. It does not provide additional cryptographic protection.

---

# Standard Input and Output

If `--input` is omitted, encryption reads from stdin.

For example:

```bash
printf '%s' 'Hello ECI2' |
    python3 pki-message-packager-eci2.py encrypt \
        --key recipient.eci2.public \
        --output message.eci2
```

Decryption can similarly write plaintext to stdout:

```bash
python3 pki-message-packager-eci2.py decrypt \
    --key recipient.eci2.private \
    --input message.eci2
```

This makes ECI2 usable in shell pipelines.

---

# Command Reference

## `keygen`

```text
keygen --private FILE --public FILE [--force]
```

Options:

| Option           | Description                       |
| ---------------- | --------------------------------- |
| `--private FILE` | Private key output                |
| `--public FILE`  | Public key output                 |
| `--force`        | Permit overwriting existing files |

---

## `encrypt`

```text
encrypt --key FILE [--message TEXT | --input FILE]
        [--output FILE] [--base64]
```

Options:

| Option           | Description               |
| ---------------- | ------------------------- |
| `--key FILE`     | ECI2 recipient public key |
| `--message TEXT` | Encrypt UTF-8 text        |
| `--input FILE`   | Encrypt a file            |
| `--output FILE`  | Package output            |
| `--base64`       | Base64-encode package     |

If neither `--message` nor `--input` is specified, plaintext is read from stdin.

`--message` and `--input` are mutually exclusive.

---

## `decrypt`

```text
decrypt --key FILE [--message TEXT | --input FILE]
        [--output FILE] [--base64]
```

Options:

| Option          | Description                 |
| --------------- | --------------------------- |
| `--key FILE`    | ECI2 recipient private key  |
| `--input FILE`  | ECI2 package                |
| `--output FILE` | Plaintext output            |
| `--base64`      | Base64-decode package first |

If `--input` is omitted, the package is read from stdin.

---

# ECI2 Package Format

An ECI2 encrypted package has the following structure:

```text
Offset       Size       Field
------------------------------------------------
0            4          Magic: "ECI2"
4            1          Protocol version
5            1          Cryptographic suite
6           32          Ephemeral X25519 public key
38        1088          ML-KEM-768 ciphertext
1126        32          HKDF salt
1158        12          AES-GCM nonce
1170         8          Ciphertext length
1178         N          AES-GCM ciphertext + tag
```

The current fixed header size is:

```text
1178 bytes
```

The AES-GCM authentication tag is included in the ciphertext length.

---

# Header Authentication

The complete ECI2 header is authenticated as AES-GCM Additional Authenticated Data (AAD).

Conceptually:

```python
ciphertext = AESGCM(key).encrypt(
    nonce,
    plaintext,
    header,
)
```

The following fields are therefore authenticated:

* protocol version
* cryptographic suite
* ephemeral X25519 public key
* ML-KEM ciphertext
* HKDF salt
* AES-GCM nonce
* ciphertext length

An attacker cannot modify these fields without causing AES-GCM authentication failure.

---

# Hybrid Key Derivation

Encryption produces two independent shared secrets:

```text
X25519 shared secret
ML-KEM-768 shared secret
```

These are combined into HKDF input using an explicit domain-separation label:

```text
"ECI2-HYBRID-IKM\0"
    || X25519 shared secret
    || ML-KEM shared secret
```

HKDF-SHA-384 then derives the 256-bit AES key:

```text
HKDF-SHA-384(
    salt = random 256-bit value,
    info = "ECI2-X25519-MLKEM768-AES256GCM\0",
    length = 32
)
```

The AES key is therefore dependent upon both key-establishment mechanisms.

---

# Security Properties

ECI2 is designed to provide:

### Confidentiality

AES-256-GCM protects the plaintext from an attacker who does not possess the recipient's private key.

### Ciphertext integrity

AES-GCM authenticates both the encrypted data and the ECI2 header.

### Classical security

X25519 provides strong conventional elliptic-curve security.

### Post-quantum protection

ML-KEM-768 provides the post-quantum KEM component.

A future quantum attacker capable of breaking X25519 does not automatically obtain the ML-KEM shared secret.

### Domain separation

The KDF explicitly identifies the ECI2 hybrid construction and cryptographic suite.

### Algorithm identification

The protocol version and cryptographic-suite identifier are included in both key containers and encrypted packages.

---

# What ECI2 Does Not Provide

ECI2 provides **recipient encryption**, not sender authentication.

Successful decryption establishes that the package was encrypted under the corresponding recipient public key, but it does not establish who created the package.

For applications requiring authenticated senders, a separate digital-signature mechanism should be added.

A suitable future design could use a PQ signature such as ML-DSA.

Do not attempt to construct a signature scheme from the ECI2 KEM primitives.

---

# Key Security

The private-key file contains sufficient material to decrypt ECI2 packages encrypted to that key.

Protect private keys accordingly.

Recommended permissions on Unix-like systems:

```bash
chmod 600 recipient.eci2.private
chmod 644 recipient.eci2.public
```

The program attempts to set the private-key file to mode `0600` when generating it.

Do not:

* commit private keys to Git
* place private keys in public repositories
* transmit private keys through untrusted channels
* reuse private keys across unrelated security domains without a deliberate key-management policy

If a private key is compromised, assume that all ECI2 packages encrypted to that key can potentially be decrypted.

---

# Key Rotation

ECI2 does not provide a key-management or certificate-management system.

Applications using ECI2 should establish their own policies for:

* key generation
* key distribution
* key rotation
* key expiration
* revocation
* backup
* destruction
* recovery

A recipient public key should have an externally managed identity and lifecycle.

---

# Size Limit

The current implementation has a nominal plaintext limit of approximately:

```text
1 GiB
```

This limit exists because the implementation reads the complete plaintext into memory and uses the one-shot `AESGCM.encrypt()` and `AESGCM.decrypt()` interfaces.

The actual memory requirement can be considerably greater than the plaintext size because encryption/decryption requires additional buffers.

For example, processing a 1 GiB file should not be interpreted as requiring only 1 GiB of RAM.

---

# Streaming Files

The current implementation is intentionally **not a streaming encryption format**.

For large files, a future ECI2 streaming format should be designed rather than simply splitting a plaintext into arbitrary pieces.

Such a format should define:

* chunk size
* chunk sequence numbers
* per-chunk nonces
* associated data
* final-chunk semantics
* total length
* truncation detection
* reordering detection
* replay considerations
* maximum number of chunks
* key derivation
* failure behavior

Do not independently invent a chunking scheme around the current ECI2 format.

---

# ECI1 Compatibility

ECI2 does **not** attempt to decrypt ECI1 packages.

The two protocols have different cryptographic properties:

```text
ECI1:
    X25519
      |
    HKDF-SHA-256
      |
    AES-256-GCM

ECI2:
    X25519 + ML-KEM-768
            |
        HKDF-SHA-384
            |
        AES-256-GCM
```

This distinction is deliberate.

Existing ECI1 packages should be treated as legacy/classical-only encrypted material.

Do not silently reinterpret an ECI1 package using ECI2 semantics.

---

# Threat Model

ECI2 is intended to protect data against an attacker who can obtain:

* the recipient public key
* the ECI2 ciphertext
* the complete ECI2 package header
* arbitrary numbers of other ECI2 ciphertexts for the same public key

The attacker is assumed not to possess the recipient's private key.

The design also considers a **harvest-now/decrypt-later** adversary who records encrypted material today and attempts to decrypt it after practical quantum computing becomes available.

The hybrid design is intended to prevent compromise of X25519 alone from being sufficient to recover the AES key.

---

# Randomness

ECI2 relies on the operating system's cryptographically secure random source through Python's `os.urandom()` and the `cryptography` library's key-generation routines.

Random values include:

* ephemeral X25519 private keys
* HKDF salts
* AES-GCM nonces

Do not replace these mechanisms with:

```python
random
```

or another non-cryptographic PRNG.

---

# Error Handling

Malformed packages are rejected rather than partially processed.

The parser validates:

* magic value
* protocol version
* cryptographic suite
* package length
* fixed-size key material
* ML-KEM ciphertext length
* salt length
* nonce length
* ciphertext length
* trailing data

Authentication failures are reported as decryption failures.

Cryptographic backend details are not intentionally exposed through the command-line error interface.

---

# Testing

At minimum, a development test suite should verify:

1. Key generation.
2. Public/private key loading.
3. Message encryption/decryption.
4. Empty-message encryption/decryption.
5. Binary data containing arbitrary byte values.
6. File encryption/decryption.
7. Base64 encoding/decoding.
8. Tampering with the ciphertext.
9. Tampering with every authenticated header field.
10. Truncated packages.
11. Appended data.
12. Incorrect ciphertext lengths.
13. Wrong private keys.
14. Wrong public keys.
15. Unsupported protocol versions.
16. Unsupported cryptographic suites.
17. Invalid key containers.
18. Maximum-size boundary behavior.
19. ML-KEM encapsulation/decapsulation consistency.
20. X25519 shared-secret consistency.

A particularly important property test is:

```text
encrypt(public_key, plaintext)
        |
        v
decrypt(private_key, package)
        |
        v
plaintext
```

and:

```text
modify(package, any authenticated byte)
        |
        v
decrypt(...)
        |
        v
FAIL
```

---

# Static Analysis

The project is intended to be compatible with Ruff.

Example:

```bash
ruff check pki-message-packager-eci2.py --extend-select F,B,UP
```

The code should also be tested with Python's compiler:

```bash
python3 -m py_compile pki-message-packager-eci2.py
```

---

# Example Round Trip

A complete example:

```bash
# Generate recipient keys.
python3 pki-message-packager-eci2.py keygen \
    --private recipient.eci2.private \
    --public recipient.eci2.public

# Encrypt.
python3 pki-message-packager-eci2.py encrypt \
    --key recipient.eci2.public \
    --message 'Post-quantum test message' \
    --output test.eci2

# Decrypt.
python3 pki-message-packager-eci2.py decrypt \
    --key recipient.eci2.private \
    --input test.eci2
```

Expected output:

```text
Post-quantum test message
```

---

# Security Considerations

## AES-GCM nonce uniqueness

The implementation generates a random 96-bit nonce for every package.

Nonce reuse with the same AES key would be dangerous.

Because each package uses fresh ephemeral X25519 and ML-KEM secrets, the resulting AES key is also fresh, providing an additional layer of protection against nonce collisions. Nevertheless, nonce uniqueness remains a protocol requirement and must not be deliberately violated.

Do not modify the implementation to use a fixed nonce.

---

## Forward secrecy

ECI2 uses an ephemeral X25519 key for each encryption operation.

However, the long-term recipient ML-KEM private key remains necessary for ML-KEM decapsulation.

The resulting construction should not automatically be assumed to provide every formal form of forward secrecy associated with interactive protocols such as TLS.

Applications with particularly demanding forward-secrecy requirements should model the complete key lifecycle and protocol rather than relying solely on the properties of this file-encryption format.

---

## Authentication

AES-GCM provides ciphertext authentication but not sender identity.

An attacker cannot modify a valid package without detection, but an attacker may be able to construct a new valid package for a recipient if they possess the recipient's public key.

This is normal public-key encryption behavior.

If sender identity matters, use an authenticated signature layer.

---

# Protocol Evolution

The ECI2 format reserves the version and cryptographic-suite fields for future expansion.

The current suite is:

```text
Version: 1
Suite:   1
```

Future versions must not silently alter the cryptographic meaning of an existing version/suite combination.

A new construction should receive a new suite identifier or protocol version.

Backward compatibility should be explicitly implemented and tested rather than inferred from package contents.

---

# Repository Layout

A recommended repository layout is:

```text
.
├── LICENSE
├── README.md
├── requirements.txt
├── pki-message-packager-eci2.py
└── tests/
    ├── test_crypto.py
    ├── test_format.py
    └── test_cli.py
```

Additional documentation can be placed under:

```text
docs/
```

A `SECURITY.md` file is also recommended for a public GitHub repository.

---

# Dependency Management

The current `requirements.txt` contains:

```text
cryptography>=47.0,<52
```

For deployment environments requiring deterministic builds, pin the exact tested dependency version and generate a separate lock/constraints file.

Do not blindly upgrade cryptographic libraries in production without running the project's interoperability and regression tests.

---

# Limitations

The current implementation intentionally does not provide:

* sender authentication
* digital signatures
* certificate management
* key revocation
* key escrow
* encrypted private-key storage
* streaming encryption
* multi-recipient packages
* key rotation
* key discovery
* interoperability with external ECIES implementations
* interoperability with arbitrary ML-KEM implementations
* protection against compromise of the recipient private key

These are application or protocol-management concerns rather than features that should be added implicitly.

---

# Security Status

This project should currently be regarded as **experimental security software**.

Although it uses established cryptographic primitives, the composition and binary protocol are application-specific.

The security of ECI2 depends on:

1. The security of X25519.
2. The security of ML-KEM-768.
3. The security of HKDF.
4. The security of AES-256-GCM.
5. Correct implementation of the protocol.
6. Correct key management.
7. Correct randomness.
8. Correct handling of private keys.

Use of a well-established primitive does not automatically make a newly designed protocol equivalent to a standardized protocol.

For high-assurance applications, have the protocol and implementation independently reviewed before deployment.

---

# License

This tool is released under the Apache 2.0 license. See the LICENSE file in this repo for details.

---

# Disclaimer

This software is provided for research, development, and security-engineering purposes.

No guarantee is made that the implementation is suitable for any particular security-sensitive application.

Cryptographic software should undergo appropriate independent review, testing, and threat modeling before being used to protect high-value or safety-critical information.
