"""
Configuration Password Encryption Utility

This module provides automatic password encryption for database configuration files.
Passwords are encrypted using Fernet (symmetric encryption) on first use and stored
as encrypted_password in the YAML configuration file.

Security Note:
    This implementation uses a hardcoded encryption key with machine-specific salting.
    It protects against casual viewing but is NOT cryptographically secure against
    determined attackers. For production environments, use environment variables,
    Azure Key Vault, or other secure key management solutions.

Usage:
    The encryption is automatic and transparent. When annotation_db_manager or
    record_batch_processor loads a config file with a plaintext 'password' field,
    it will automatically:
    1. Encrypt the password
    2. Write it as 'encrypted_password' field
    3. Remove the plaintext 'password' field
    4. Save the updated YAML file

    Subsequent runs will use the encrypted password automatically.
"""

import os
import base64
import hashlib
import socket
from typing import Optional

try:
    from cryptography.fernet import Fernet
except ImportError:
    raise ImportError(
        "The 'cryptography' package is required for password encryption. "
        "Install it with: pip install cryptography>=41.0.0"
    )


# Base obfuscation key (not secret, just obfuscation)
# This is combined with machine-specific data for per-machine variation
_BASE_KEY_MATERIAL = b"ThriftAnnotations_DB_Password_Encryption_v1_2024"


def _get_machine_salt() -> bytes:
    """
    Generate a machine-specific salt based on hostname.

    This provides basic per-machine variation but is not cryptographically secure.
    The same machine will always generate the same salt.

    Returns:
        bytes: Machine-specific salt
    """
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "default_host"

    return hostname.encode('utf-8')


def _derive_encryption_key() -> bytes:
    """
    Derive a Fernet-compatible encryption key.

    Combines base key material with machine-specific salt to create
    a deterministic but machine-specific encryption key.

    Returns:
        bytes: Base64-encoded 32-byte key suitable for Fernet
    """
    # Combine base material with machine salt
    salt = _get_machine_salt()
    combined = _BASE_KEY_MATERIAL + salt

    # Derive a 32-byte key using SHA256
    key_bytes = hashlib.sha256(combined).digest()

    # Fernet requires base64-encoded key
    key_b64 = base64.urlsafe_b64encode(key_bytes)

    return key_b64


def get_fernet() -> Fernet:
    """
    Get a Fernet cipher instance with the derived key.

    Returns:
        Fernet: Initialized Fernet cipher
    """
    key = _derive_encryption_key()
    return Fernet(key)


def encrypt_password(plaintext: str) -> str:
    """
    Encrypt a plaintext password.

    Args:
        plaintext: The plaintext password to encrypt

    Returns:
        str: Base64-encoded encrypted password (starts with 'gAAAAAB')

    Example:
        >>> encrypted = encrypt_password("my_secret_password")
        >>> print(encrypted)
        gAAAAABmK8x7...
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty password")

    fernet = get_fernet()
    encrypted_bytes = fernet.encrypt(plaintext.encode('utf-8'))

    # Return as string for YAML storage
    return encrypted_bytes.decode('ascii')


def decrypt_password(encrypted: str) -> str:
    """
    Decrypt an encrypted password.

    Args:
        encrypted: The encrypted password string (from encrypted_password field)

    Returns:
        str: The decrypted plaintext password

    Raises:
        ValueError: If decryption fails (corrupted or wrong key)

    Example:
        >>> plaintext = decrypt_password("gAAAAABmK8x7...")
        >>> # Use plaintext for database connection
    """
    if not encrypted:
        raise ValueError("Cannot decrypt empty password")

    try:
        fernet = get_fernet()
        decrypted_bytes = fernet.decrypt(encrypted.encode('ascii'))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(
            f"Failed to decrypt password. The encrypted password may be corrupted "
            f"or was encrypted on a different machine. Error: {e}"
        )


def is_encrypted_password(value: str) -> bool:
    """
    Check if a string looks like an encrypted password.

    Fernet tokens always start with 'gAAAAAB' in base64 encoding.

    Args:
        value: The string to check

    Returns:
        bool: True if the string appears to be encrypted
    """
    return value.startswith('gAAAAAB')


def test_encryption_roundtrip(test_password: str = "test_password_123") -> bool:
    """
    Test encryption and decryption roundtrip.

    Args:
        test_password: Password to use for testing

    Returns:
        bool: True if roundtrip successful, False otherwise
    """
    try:
        encrypted = encrypt_password(test_password)
        decrypted = decrypt_password(encrypted)
        return decrypted == test_password
    except Exception as e:
        print(f"Encryption test failed: {e}")
        return False


if __name__ == "__main__":
    """
    Test/demo mode - shows encryption and decryption examples.
    """
    print("=" * 80)
    print("Configuration Password Encryption Utility - Test Mode")
    print("=" * 80)

    # Test encryption
    test_password = "MyTestPassword123!"
    print(f"\n1. Testing encryption/decryption roundtrip...")
    print(f"   Original password: {test_password}")

    encrypted = encrypt_password(test_password)
    print(f"   Encrypted:         {encrypted}")

    decrypted = decrypt_password(encrypted)
    print(f"   Decrypted:         {decrypted}")

    if decrypted == test_password:
        print("   [OK] Roundtrip successful!")
    else:
        print("   [FAIL] Roundtrip failed!")

    # Show machine info
    print(f"\n2. Machine information:")
    print(f"   Hostname: {socket.gethostname()}")
    print(f"   Machine salt: {_get_machine_salt().decode('utf-8')}")

    # Test is_encrypted check
    print(f"\n3. Testing encryption detection:")
    print(f"   is_encrypted('plaintext'): {is_encrypted_password('plaintext')}")
    print(f"   is_encrypted('{encrypted[:20]}...'): {is_encrypted_password(encrypted)}")

    # Full roundtrip test
    print(f"\n4. Running full roundtrip test...")
    if test_encryption_roundtrip():
        print("   [OK] Full test passed!")
    else:
        print("   [FAIL] Full test failed!")

    print("\n" + "=" * 80)
    print("Note: The same password encrypted on different machines will produce")
    print("different encrypted values due to machine-specific salting.")
    print("=" * 80)
