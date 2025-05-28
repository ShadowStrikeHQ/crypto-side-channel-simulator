import argparse
import logging
import time
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Core Functions ---

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Simulates timing and power side-channel attacks on cryptographic implementations.")
    parser.add_argument("operation", choices=['rsa_keygen', 'rsa_encrypt', 'rsa_decrypt', 'aes_encrypt', 'aes_decrypt', 'hash', 'hmac', 'pbkdf2'], help="The cryptographic operation to simulate.")
    parser.add_argument("--key_size", type=int, default=2048, help="Key size for RSA (default: 2048).  Only applies to rsa_keygen.")
    parser.add_argument("--data_size", type=int, default=128, help="Data size in bytes for encryption/hashing (default: 128).")
    parser.add_argument("--iterations", type=int, default=1000, help="Number of iterations for PBKDF2 (default: 1000).")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--show_time", action="store_true", help="Show time taken for the operation.")
    return parser.parse_args()


def simulate_timing_variation(base_time, variation_percentage=0.1):
    """
    Simulates timing variation based on side-channel leakage.

    Args:
        base_time (float): The base execution time.
        variation_percentage (float): The percentage of variation (default: 0.1).

    Returns:
        float: The simulated execution time with variation.
    """
    variation = base_time * variation_percentage * random.uniform(-1, 1)
    return base_time + variation


def rsa_keygen_simulation(key_size=2048):
    """
    Simulates RSA key generation with timing variation.

    Args:
        key_size (int): The size of the RSA key to generate.

    Returns:
        rsa.RSAPrivateKey: The generated RSA private key.
    """
    start_time = time.time()
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"RSA key generation (size={key_size}) simulated time: {simulated_time:.6f} seconds")
        return private_key
    except Exception as e:
        logging.error(f"Error during RSA key generation: {e}")
        return None


def rsa_encrypt_simulation(private_key, data):
    """
    Simulates RSA encryption with timing variation.

    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key to use.
        data (bytes): The data to encrypt.

    Returns:
        bytes: The encrypted data.
    """
    if not isinstance(data, bytes):
        raise ValueError("Data must be bytes.")

    start_time = time.time()
    try:
        public_key = private_key.public_key()

        # PKCS1v1.5 padding is vulnerable to Bleichenbacher attacks, but used here for demonstration simplicity.
        ciphertext = public_key.encrypt(
            data,
            padding.PKCS1v15()
        )

        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"RSA encryption simulated time: {simulated_time:.6f} seconds")
        return ciphertext
    except Exception as e:
        logging.error(f"Error during RSA encryption: {e}")
        return None


def rsa_decrypt_simulation(private_key, ciphertext):
    """
    Simulates RSA decryption with timing variation.

    Args:
        private_key (rsa.RSAPrivateKey): The RSA private key to use.
        ciphertext (bytes): The ciphertext to decrypt.

    Returns:
        bytes: The decrypted data.
    """
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes.")

    start_time = time.time()
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"RSA decryption simulated time: {simulated_time:.6f} seconds")
        return plaintext
    except Exception as e:
        logging.error(f"Error during RSA decryption: {e}")
        return None


def aes_encrypt_simulation(key, data):
    """
    Simulates AES encryption with timing variation.

    Args:
        key (bytes): The AES key to use.
        data (bytes): The data to encrypt.

    Returns:
        bytes: The encrypted data.
    """
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes.")
    if not isinstance(data, bytes):
        raise ValueError("Data must be bytes.")

    start_time = time.time()
    try:
        iv = os.urandom(16) # Initialization Vector
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"AES encryption simulated time: {simulated_time:.6f} seconds")
        return iv, ciphertext
    except Exception as e:
        logging.error(f"Error during AES encryption: {e}")
        return None, None


def aes_decrypt_simulation(key, iv, ciphertext):
    """
    Simulates AES decryption with timing variation.

    Args:
        key (bytes): The AES key to use.
        iv (bytes): The Initialization Vector used for encryption.
        ciphertext (bytes): The ciphertext to decrypt.

    Returns:
        bytes: The decrypted data.
    """
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes.")
    if not isinstance(iv, bytes):
        raise ValueError("IV must be bytes.")
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes.")

    start_time = time.time()
    try:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"AES decryption simulated time: {simulated_time:.6f} seconds")
        return plaintext
    except Exception as e:
        logging.error(f"Error during AES decryption: {e}")
        return None


def hash_simulation(data, algorithm='sha256'):
    """
    Simulates hashing with timing variation.

    Args:
        data (bytes): The data to hash.
        algorithm (str): The hashing algorithm to use (default: 'sha256').

    Returns:
        bytes: The hash digest.
    """
    if not isinstance(data, bytes):
        raise ValueError("Data must be bytes.")

    start_time = time.time()
    try:
        if algorithm == 'sha256':
            hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        elif algorithm == 'sha512':
            hasher = hashes.Hash(hashes.SHA512(), backend=default_backend())
        else:
            raise ValueError("Unsupported hash algorithm.")

        hasher.update(data)
        digest = hasher.finalize()
        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"{algorithm} hashing simulated time: {simulated_time:.6f} seconds")
        return digest
    except Exception as e:
        logging.error(f"Error during {algorithm} hashing: {e}")
        return None


def hmac_simulation(key, data, algorithm='sha256'):
    """
    Simulates HMAC with timing variation.

    Args:
        key (bytes): The HMAC key.
        data (bytes): The data to HMAC.
        algorithm (str): The hashing algorithm to use (default: 'sha256').

    Returns:
        bytes: The HMAC digest.
    """
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes.")
    if not isinstance(data, bytes):
        raise ValueError("Data must be bytes.")

    start_time = time.time()
    try:
        if algorithm == 'sha256':
            hmac_obj = HMAC(key, hashes.SHA256(), backend=default_backend())
        elif algorithm == 'sha512':
            hmac_obj = HMAC(key, hashes.SHA512(), backend=default_backend())
        else:
            raise ValueError("Unsupported HMAC algorithm.")
        hmac_obj.update(data)
        digest = hmac_obj.finalize()
        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"{algorithm} HMAC simulated time: {simulated_time:.6f} seconds")
        return digest
    except Exception as e:
        logging.error(f"Error during {algorithm} HMAC: {e}")
        return None


def pbkdf2_simulation(password, salt, iterations=1000, algorithm='sha256'):
    """
    Simulates PBKDF2 with timing variation.

    Args:
        password (bytes): The password.
        salt (bytes): The salt.
        iterations (int): The number of iterations (default: 1000).
        algorithm (str): The hashing algorithm to use (default: 'sha256').

    Returns:
        bytes: The derived key.
    """
    if not isinstance(password, bytes):
        raise ValueError("Password must be bytes.")
    if not isinstance(salt, bytes):
        raise ValueError("Salt must be bytes.")

    start_time = time.time()
    try:
        if algorithm == 'sha256':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
        elif algorithm == 'sha512':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
        else:
            raise ValueError("Unsupported PBKDF2 algorithm.")

        derived_key = kdf.derive(password)
        end_time = time.time()
        base_time = end_time - start_time
        simulated_time = simulate_timing_variation(base_time)
        logging.info(f"PBKDF2 ({algorithm}, iterations={iterations}) simulated time: {simulated_time:.6f} seconds")
        return derived_key
    except Exception as e:
        logging.error(f"Error during PBKDF2 ({algorithm}): {e}")
        return None


def main():
    """
    Main function to parse arguments and run the selected simulation.
    """
    args = setup_argparse()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        if args.operation == 'rsa_keygen':
            rsa_keygen_simulation(args.key_size)
        elif args.operation == 'rsa_encrypt':
            private_key = rsa_keygen_simulation(args.key_size)
            if private_key:
                data = os.urandom(args.data_size)
                rsa_encrypt_simulation(private_key, data)
        elif args.operation == 'rsa_decrypt':
            private_key = rsa_keygen_simulation(args.key_size)
            if private_key:
                data = os.urandom(args.data_size)
                ciphertext = rsa_encrypt_simulation(private_key, data)
                if ciphertext:
                    rsa_decrypt_simulation(private_key, ciphertext)
        elif args.operation == 'aes_encrypt':
            key = os.urandom(32)  # AES-256 key
            data = os.urandom(args.data_size)
            aes_encrypt_simulation(key, data)
        elif args.operation == 'aes_decrypt':
            key = os.urandom(32)  # AES-256 key
            data = os.urandom(args.data_size)
            iv, ciphertext = aes_encrypt_simulation(key, data)
            if iv and ciphertext:
                 aes_decrypt_simulation(key, iv, ciphertext)

        elif args.operation == 'hash':
            data = os.urandom(args.data_size)
            hash_simulation(data)
        elif args.operation == 'hmac':
            key = os.urandom(32)
            data = os.urandom(args.data_size)
            hmac_simulation(key, data)
        elif args.operation == 'pbkdf2':
            password = b"password123"
            salt = os.urandom(16)
            pbkdf2_simulation(password, salt, args.iterations)

        if args.show_time:
           logging.info("Showing time is enabled.  The simulated times are already logged.")


    except ValueError as e:
        logging.error(f"Invalid input: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()