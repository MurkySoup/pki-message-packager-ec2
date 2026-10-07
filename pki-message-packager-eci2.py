#!/usr/bin/env python3
# Linter: ruff check pki-message-packager-eci2.py --extend-select F,B,UP


"""
pki-message-packager-eci2.py - ECI2: Hybrid post-quantum PKI message packaging.

Cryptographic suite:
  X25519 + ML-KEM-768 + HKDF-SHA-384 + AES-256-GCM

ECI2 is intentionally incompatible with ECI1.

Requirements:
- Python 3.11+
- cryptography >= 47.0

The implementation is intended for messages/files of approximately 1 GiB
or less. The complete plaintext is held in memory during encryption/decryption.

Key files use an ECI2-specific binary container containing raw X25519 and
ML-KEM key material. They are not PEM files.

Public key:
- E2PK
- version
- suite
- X25519 public key (32 bytes)
- ML-KEM-768 public key (1184 bytes)

Private key:
- E2SK
- version
- suite
- X25519 private key (32 bytes)
- ML-KEM-768 seed (64 bytes)

Message package:
- ECI2
- version
- suite
- X25519 ephemeral public key (32 bytes)
- ML-KEM-768 ciphertext (1088 bytes)
- HKDF salt (32 bytes)
- AES-GCM nonce (12 bytes)
- ciphertext length (8 bytes, big endian)
- AES-GCM ciphertext + authentication tag

The complete package header, including ciphertext length, is authenticated
as AES-GCM AAD.
"""


from __future__ import annotations
import argparse
import base64
import binascii
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from cryptography import __version__ as cryptography_version
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------


PACKAGE_MAGIC = b"ECI2"
PUBLIC_KEY_MAGIC = b"E2PK"
PRIVATE_KEY_MAGIC = b"E2SK"

PROTOCOL_VERSION = 1

SUITE_X25519_MLKEM768_AES256GCM = 1
SUPPORTED_SUITE = SUITE_X25519_MLKEM768_AES256GCM

AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
HKDF_SALT_SIZE = 32

X25519_KEY_SIZE = 32
MLKEM768_PUBLIC_KEY_SIZE = 1184
MLKEM768_PRIVATE_SEED_SIZE = 64
MLKEM768_CIPHERTEXT_SIZE = 1088
MLKEM768_SHARED_SECRET_SIZE = 32

# ECI2 package header:
#
#   MAGIC          4
#   VERSION        1
#   SUITE          1
#   X25519 EPH    32
#   ML-KEM CT   1088
#   SALT          32
#   NONCE         12
#   CT LENGTH      8
#

PACKAGE_HEADER_SIZE = (
    len(PACKAGE_MAGIC)
    + 1
    + 1
    + X25519_KEY_SIZE
    + MLKEM768_CIPHERTEXT_SIZE
    + HKDF_SALT_SIZE
    + GCM_NONCE_SIZE
    + 8
)

MAX_MESSAGE_SIZE = 1024 * 1024 * 1024  # 1 GiB

# Domain separation is deliberately explicit.
KDF_IKM_LABEL = b"ECI2-HYBRID-IKM\x00"
KDF_INFO = b"ECI2-X25519-MLKEM768-AES256GCM\x00"


class PKIError(Exception):
    """Base exception for ECI2 PKI packaging errors."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicKey:
    """ECI2 recipient public key."""

    x25519: x25519.X25519PublicKey
    mlkem: mlkem.MLKEM768PublicKey


@dataclass(frozen=True)
class PrivateKey:
    """ECI2 recipient private key."""

    x25519: x25519.X25519PrivateKey
    mlkem: mlkem.MLKEM768PrivateKey


@dataclass(frozen=True)
class PackageHeader:
    """Parsed ECI2 package header."""

    version: int
    suite: int
    ephemeral_x25519: bytes
    mlkem_ciphertext: bytes
    salt: bytes
    nonce: bytes
    ciphertext_length: int

    def serialize(self) -> bytes:
        """Serialize the header exactly as represented on the wire."""
        return b"".join(
            (
                PACKAGE_MAGIC,
                struct.pack(">B", self.version),
                struct.pack(">B", self.suite),
                self.ephemeral_x25519,
                self.mlkem_ciphertext,
                self.salt,
                self.nonce,
                struct.pack(">Q", self.ciphertext_length),
            )
        )


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _fail(message: str) -> None:
    """Raise a protocol error."""
    raise PKIError(message)


def _check_cryptography_version() -> None:
    """Verify that the installed cryptography version is ML-KEM capable."""
    try:
        major, minor, *_ = (
            int(part) for part in cryptography_version.split(".")
        )
    except ValueError as exc:
        raise PKIError(
            f"Unable to determine cryptography version: "
            f"{cryptography_version}"
        ) from exc

    if (major, minor) < (47, 0):
        raise PKIError(
            "cryptography >= 47.0 is required for ML-KEM support; "
            f"installed version is {cryptography_version}"
        )


def _write_private_file(path: Path, data: bytes) -> None:
    """Write private key data and restrict permissions where possible."""
    path.write_bytes(data)

    try:
        path.chmod(0o600)
    except OSError:
        # chmod is not meaningful on some platforms/filesystems.
        pass


def _read_exact(data: bytes, offset: int, length: int, field: str) -> bytes:
    """Read an exact byte range from an in-memory buffer."""
    end = offset + length

    if offset < 0 or end > len(data):
        raise PKIError(f"Truncated {field}")

    return data[offset:end]


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ECI2 X25519 + ML-KEM-768 keypair.

    Returns:
        Tuple containing private-key container bytes and public-key
        container bytes.
    """
    _check_cryptography_version()

    try:
        x25519_private = x25519.X25519PrivateKey.generate()
        mlkem_private = mlkem.MLKEM768PrivateKey.generate()
    except UnsupportedAlgorithm as exc:
        raise PKIError(
            "ML-KEM-768 is not supported by the installed cryptography "
            "backend"
        ) from exc

    x25519_private_bytes = x25519_private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

    x25519_public_bytes = x25519_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    mlkem_private_seed = mlkem_private.private_bytes_raw()

    mlkem_public_bytes = mlkem_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    private_data = b"".join(
        (
            PRIVATE_KEY_MAGIC,
            struct.pack(">B", PROTOCOL_VERSION),
            struct.pack(">B", SUPPORTED_SUITE),
            x25519_private_bytes,
            mlkem_private_seed,
        )
    )

    public_data = b"".join(
        (
            PUBLIC_KEY_MAGIC,
            struct.pack(">B", PROTOCOL_VERSION),
            struct.pack(">B", SUPPORTED_SUITE),
            x25519_public_bytes,
            mlkem_public_bytes,
        )
    )

    return private_data, public_data


def load_public_key(path: Path) -> PublicKey:
    """Load an ECI2 public key container."""
    data = path.read_bytes()

    expected_size = (
        len(PUBLIC_KEY_MAGIC)
        + 1
        + 1
        + X25519_KEY_SIZE
        + MLKEM768_PUBLIC_KEY_SIZE
    )

    if len(data) != expected_size:
        raise PKIError(
            f"Invalid public key size: expected {expected_size} bytes, "
            f"got {len(data)}"
        )

    if data[:4] != PUBLIC_KEY_MAGIC:
        raise PKIError("Invalid ECI2 public key format")

    version = data[4]
    suite = data[5]

    if version != PROTOCOL_VERSION:
        raise PKIError(f"Unsupported public key version: {version}")

    if suite != SUPPORTED_SUITE:
        raise PKIError(f"Unsupported public key suite: {suite}")

    x25519_bytes = data[6:38]
    mlkem_bytes = data[38:]

    try:
        x25519_public = x25519.X25519PublicKey.from_public_bytes(
            x25519_bytes
        )
        mlkem_public = mlkem.MLKEM768PublicKey.from_public_bytes(
            mlkem_bytes
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise PKIError("Invalid ECI2 public key") from exc

    return PublicKey(
        x25519=x25519_public,
        mlkem=mlkem_public,
    )


def load_private_key(path: Path) -> PrivateKey:
    """Load an ECI2 private key container."""
    data = path.read_bytes()

    expected_size = (
        len(PRIVATE_KEY_MAGIC)
        + 1
        + 1
        + X25519_KEY_SIZE
        + MLKEM768_PRIVATE_SEED_SIZE
    )

    if len(data) != expected_size:
        raise PKIError(
            f"Invalid private key size: expected {expected_size} bytes, "
            f"got {len(data)}"
        )

    if data[:4] != PRIVATE_KEY_MAGIC:
        raise PKIError("Invalid ECI2 private key format")

    version = data[4]
    suite = data[5]

    if version != PROTOCOL_VERSION:
        raise PKIError(f"Unsupported private key version: {version}")

    if suite != SUPPORTED_SUITE:
        raise PKIError(f"Unsupported private key suite: {suite}")

    x25519_bytes = data[6:38]
    mlkem_seed = data[38:]

    try:
        x25519_private = x25519.X25519PrivateKey.from_private_bytes(
            x25519_bytes
        )
        mlkem_private = mlkem.MLKEM768PrivateKey.from_seed_bytes(
            mlkem_seed
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise PKIError("Invalid ECI2 private key") from exc

    return PrivateKey(
        x25519=x25519_private,
        mlkem=mlkem_private,
    )


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------


def derive_key(
    x25519_secret: bytes,
    mlkem_secret: bytes,
    salt: bytes,
) -> bytes:
    """
    Combine the classical and PQ shared secrets into an AES-256 key.

    Both inputs are fixed-size secrets generated by their respective
    cryptographic mechanisms.
    """
    if len(x25519_secret) != X25519_KEY_SIZE:
        raise PKIError("Invalid X25519 shared-secret length")

    if len(mlkem_secret) != MLKEM768_SHARED_SECRET_SIZE:
        raise PKIError("Invalid ML-KEM shared-secret length")

    if len(salt) != HKDF_SALT_SIZE:
        raise PKIError("Invalid HKDF salt length")

    ikm = KDF_IKM_LABEL + x25519_secret + mlkem_secret

    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=KDF_INFO,
    )

    return hkdf.derive(ikm)


# ---------------------------------------------------------------------------
# Binary package format
# ---------------------------------------------------------------------------


def _build_header(
    ephemeral_x25519: bytes,
    mlkem_ciphertext: bytes,
    salt: bytes,
    nonce: bytes,
    ciphertext_length: int,
) -> bytes:
    """Build and validate an ECI2 package header."""
    if len(ephemeral_x25519) != X25519_KEY_SIZE:
        raise PKIError("Invalid ephemeral X25519 key length")

    if len(mlkem_ciphertext) != MLKEM768_CIPHERTEXT_SIZE:
        raise PKIError("Invalid ML-KEM ciphertext length")

    if len(salt) != HKDF_SALT_SIZE:
        raise PKIError("Invalid salt length")

    if len(nonce) != GCM_NONCE_SIZE:
        raise PKIError("Invalid AES-GCM nonce length")

    if ciphertext_length < GCM_TAG_SIZE:
        raise PKIError("Ciphertext is shorter than the AES-GCM tag")

    if ciphertext_length > MAX_MESSAGE_SIZE + GCM_TAG_SIZE:
        raise PKIError("Ciphertext exceeds the configured maximum size")

    header = PackageHeader(
        version=PROTOCOL_VERSION,
        suite=SUPPORTED_SUITE,
        ephemeral_x25519=ephemeral_x25519,
        mlkem_ciphertext=mlkem_ciphertext,
        salt=salt,
        nonce=nonce,
        ciphertext_length=ciphertext_length,
    )

    serialized = header.serialize()

    if len(serialized) != PACKAGE_HEADER_SIZE:
        raise PKIError("Internal ECI2 header-size error")

    return serialized


def _parse_header(data: bytes) -> PackageHeader:
    """Parse and strictly validate an ECI2 package header."""
    if len(data) < PACKAGE_HEADER_SIZE:
        raise PKIError("Truncated ECI2 package")

    if data[:4] != PACKAGE_MAGIC:
        raise PKIError("Invalid ECI2 package magic")

    version = data[4]
    suite = data[5]

    if version != PROTOCOL_VERSION:
        raise PKIError(f"Unsupported ECI2 version: {version}")

    if suite != SUPPORTED_SUITE:
        raise PKIError(f"Unsupported ECI2 cryptographic suite: {suite}")

    offset = 6

    ephemeral_x25519 = _read_exact(
        data,
        offset,
        X25519_KEY_SIZE,
        "ephemeral X25519 key",
    )
    offset += X25519_KEY_SIZE

    mlkem_ciphertext = _read_exact(
        data,
        offset,
        MLKEM768_CIPHERTEXT_SIZE,
        "ML-KEM ciphertext",
    )
    offset += MLKEM768_CIPHERTEXT_SIZE

    salt = _read_exact(
        data,
        offset,
        HKDF_SALT_SIZE,
        "HKDF salt",
    )
    offset += HKDF_SALT_SIZE

    nonce = _read_exact(
        data,
        offset,
        GCM_NONCE_SIZE,
        "AES-GCM nonce",
    )
    offset += GCM_NONCE_SIZE

    length_bytes = _read_exact(
        data,
        offset,
        8,
        "ciphertext length",
    )

    ciphertext_length = struct.unpack(">Q", length_bytes)[0]

    if ciphertext_length < GCM_TAG_SIZE:
        raise PKIError("Invalid ciphertext length")

    if ciphertext_length > MAX_MESSAGE_SIZE + GCM_TAG_SIZE:
        raise PKIError("Ciphertext exceeds the configured maximum size")

    return PackageHeader(
        version=version,
        suite=suite,
        ephemeral_x25519=ephemeral_x25519,
        mlkem_ciphertext=mlkem_ciphertext,
        salt=salt,
        nonce=nonce,
        ciphertext_length=ciphertext_length,
    )


def _unpack(
    data: bytes,
) -> tuple[PackageHeader, bytes]:
    """Parse a complete ECI2 package."""
    header = _parse_header(data)

    if len(data) != PACKAGE_HEADER_SIZE + header.ciphertext_length:
        raise PKIError(
            "Package length does not match the declared ciphertext length"
        )

    ciphertext = data[
        PACKAGE_HEADER_SIZE:
        PACKAGE_HEADER_SIZE + header.ciphertext_length
    ]

    return header, ciphertext


# ---------------------------------------------------------------------------
# Encryption/decryption
# ---------------------------------------------------------------------------


def encrypt_message(
    public_key: PublicKey,
    message: bytes,
) -> bytes:
    """
    Encrypt a message using the ECI2 hybrid construction.

    ECI2 derives the AES key from both:
        X25519 shared secret
        ML-KEM-768 shared secret
    """
    if len(message) > MAX_MESSAGE_SIZE:
        raise PKIError("Message exceeds the configured 1 GiB limit")

    ephemeral_private = x25519.X25519PrivateKey.generate()

    try:
        x25519_secret = ephemeral_private.exchange(
            public_key.x25519
        )
    except ValueError as exc:
        raise PKIError("X25519 key exchange failed") from exc

    try:
        mlkem_secret, mlkem_ciphertext = (
            public_key.mlkem.encapsulate()
        )
    except (UnsupportedAlgorithm, ValueError) as exc:
        raise PKIError("ML-KEM encapsulation failed") from exc

    salt = os.urandom(HKDF_SALT_SIZE)
    nonce = os.urandom(GCM_NONCE_SIZE)

    aes_key = derive_key(
        x25519_secret,
        mlkem_secret,
        salt,
    )

    ciphertext_length = len(message) + GCM_TAG_SIZE

    ephemeral_x25519 = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    header = _build_header(
        ephemeral_x25519=ephemeral_x25519,
        mlkem_ciphertext=mlkem_ciphertext,
        salt=salt,
        nonce=nonce,
        ciphertext_length=ciphertext_length,
    )

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        message,
        header,
    )

    if len(ciphertext) != ciphertext_length:
        raise PKIError("Internal AES-GCM ciphertext length error")

    return header + ciphertext


def decrypt_message(
    private_key: PrivateKey,
    package: bytes,
) -> bytes:
    """Decrypt and authenticate a complete ECI2 package."""
    header, ciphertext = _unpack(package)

    try:
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            header.ephemeral_x25519
        )
    except (TypeError, ValueError) as exc:
        raise PKIError("Invalid ephemeral X25519 public key") from exc

    try:
        x25519_secret = private_key.x25519.exchange(
            ephemeral_public
        )
    except ValueError as exc:
        raise PKIError("X25519 key exchange failed") from exc

    try:
        mlkem_secret = private_key.mlkem.decapsulate(
            header.mlkem_ciphertext
        )
    except (UnsupportedAlgorithm, ValueError) as exc:
        raise PKIError("ML-KEM decapsulation failed") from exc

    aes_key = derive_key(
        x25519_secret,
        mlkem_secret,
        header.salt,
    )

    try:
        return AESGCM(aes_key).decrypt(
            header.nonce,
            ciphertext,
            header.serialize(),
        )
    except ValueError as exc:
        # AESGCM uses InvalidTag for authentication failure.
        # ValueError is retained here for defensive compatibility.
        raise PKIError("AES-GCM authentication failed") from exc
    except Exception as exc:
        # Do not expose cryptographic backend details to the CLI.
        raise PKIError("AES-GCM authentication failed") from exc


# ---------------------------------------------------------------------------
# Input/output helpers
# ---------------------------------------------------------------------------


def read_input(args: argparse.Namespace) -> bytes:
    """Read binary or textual CLI input."""
    if args.message is not None:
        return args.message.encode("utf-8")

    if args.input is not None:
        return Path(args.input).read_bytes()

    return sys.stdin.buffer.read()


def write_output(data: bytes, args: argparse.Namespace) -> None:
    """Write binary output to a file or stdout."""
    if args.output is not None:
        Path(args.output).write_bytes(data)
        return

    sys.stdout.buffer.write(data)


def decode_base64(data: bytes) -> bytes:
    """Decode base64 strictly."""
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PKIError("Invalid base64 input") from exc


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate an ECI2 recipient keypair."""
    private_data, public_data = generate_keypair()

    private_path = Path(args.private)
    public_path = Path(args.public)

    if private_path.exists() and not args.force:
        raise PKIError(
            f"Private key already exists: {private_path} "
            "(use --force to overwrite)"
        )

    if public_path.exists() and not args.force:
        raise PKIError(
            f"Public key already exists: {public_path} "
            "(use --force to overwrite)"
        )

    _write_private_file(private_path, private_data)
    public_path.write_bytes(public_data)

    print(
        f"Generated ECI2 ML-KEM-768 + X25519 keypair:\n"
        f"  private: {private_path}\n"
        f"  public:  {public_path}",
        file=sys.stderr,
    )


def cmd_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a message/file."""
    public_key = load_public_key(Path(args.key))
    message = read_input(args)

    package = encrypt_message(public_key, message)

    if args.base64:
        package = base64.b64encode(package)

    write_output(package, args)


def cmd_decrypt(args: argparse.Namespace) -> None:
    """Decrypt an ECI2 package."""
    private_key = load_private_key(Path(args.key))
    package = read_input(args)

    if args.base64:
        package = decode_base64(package)

    plaintext = decrypt_message(private_key, package)
    write_output(plaintext, args)


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------


def add_input_arguments(parser: argparse.ArgumentParser) -> None:
    """Add mutually exclusive message/input arguments."""
    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--message",
        help="message text",
    )

    group.add_argument(
        "--input",
        metavar="FILE",
        help="input file; otherwise stdin",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description=(
            "ECI2 hybrid post-quantum message packager "
            "(X25519 + ML-KEM-768 + AES-256-GCM)"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ECI2 1.0; cryptography {cryptography_version}",
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ------------------------------------------------------------------
    # keygen
    # ------------------------------------------------------------------

    keygen = sub.add_parser(
        "keygen",
        help="generate an ECI2 X25519 + ML-KEM-768 keypair",
    )

    keygen.add_argument(
        "--private",
        required=True,
        metavar="FILE",
        help="private-key filename",
    )

    keygen.add_argument(
        "--public",
        required=True,
        metavar="FILE",
        help="public-key filename",
    )

    keygen.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing key files",
    )

    keygen.set_defaults(func=cmd_keygen)

    # ------------------------------------------------------------------
    # encrypt
    # ------------------------------------------------------------------

    encrypt = sub.add_parser(
        "encrypt",
        help="encrypt a message or file",
    )

    encrypt.add_argument(
        "--key",
        required=True,
        metavar="FILE",
        help="ECI2 recipient public key",
    )

    add_input_arguments(encrypt)

    encrypt.add_argument(
        "--output",
        metavar="FILE",
        help="output package file; otherwise stdout",
    )

    encrypt.add_argument(
        "--base64",
        action="store_true",
        help="base64-encode the resulting package",
    )

    encrypt.set_defaults(func=cmd_encrypt)

    # ------------------------------------------------------------------
    # decrypt
    # ------------------------------------------------------------------

    decrypt = sub.add_parser(
        "decrypt",
        help="decrypt an ECI2 package",
    )

    decrypt.add_argument(
        "--key",
        required=True,
        metavar="FILE",
        help="ECI2 recipient private key",
    )

    add_input_arguments(decrypt)

    decrypt.add_argument(
        "--output",
        metavar="FILE",
        help="plaintext output file; otherwise stdout",
    )

    decrypt.add_argument(
        "--base64",
        action="store_true",
        help="base64-decode the input package first",
    )

    decrypt.set_defaults(func=cmd_decrypt)

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Program entry point."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except (PKIError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# end of script
