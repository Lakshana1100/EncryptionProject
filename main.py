import os
import json
import argparse
import time
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# The below configuration will be considered by default, when the config.jason/custom file is unavailable
DEFAULT_CONFIG = {
    'encryption_algorithm': 'AES256',
    'hash_algorithm': 'SHA256',
    'kdf_iterations': 100000
}

# Loading/parsing in the config file
def load_config(config_file):
    if config_file:
        with open(config_file, 'r') as file:
            return json.load(file)
    return DEFAULT_CONFIG

''' Deriving the master key/derived key via PDKDF#2, using the inbuilt python function.
The required parameters are provided below, where as the iteration count is chosen by best_iteration_count function below and
the key length is according to the encryption algorithm selected '''
def derive_key(password, salt, iterations, key_length, hash_algorithm):
    kdf = PBKDF2HMAC(
        algorithm=getattr(hashes, hash_algorithm)(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_data(plaintext, encryption_key, algorithm_name, hmac_key, hash_algorithm):
    # Below initializes the cipher object 
    if algorithm_name.startswith('AES'):
        block_size = 16
    elif algorithm_name == 'TripleDES':
        block_size = 8
    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm_name}")

    # Generating random initialization vector (IV) using the random function
    iv = os.urandom(block_size)

    # Create a cipher object
    if algorithm_name.startswith('AES'):
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    else:
        cipher = Cipher(algorithms.TripleDES(encryption_key), modes.CBC(iv), backend=default_backend())

    encryptor = cipher.encryptor()

    # Padding the plaintext using PKCS7, to support both AES and 3DES. 
    padder = padding.PKCS7(block_size * 8).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypting the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Calculating the HMAC key - including the initialization vector and cipher text
    hmac_obj = hmac.HMAC(hmac_key, getattr(hashes, hash_algorithm)(), backend=default_backend())
    hmac_obj.update(iv + ciphertext)
    hmac_value = hmac_obj.finalize()

    ''' Returning the concatenatation of the cipher text, hmac value, and initialization vetor rather than adding them to meta data 
     for enhanced security, making it challenging for the attackers to figure out the exact cipher text.  '''
    return iv + ciphertext + hmac_value

def decrypt_data(ciphertext, encryption_key, algorithm_name, hmac_key, hash_algorithm):
    # Assigning block size 
    if algorithm_name.startswith('AES'):
        block_size = 16
    elif algorithm_name == 'TripleDES':
        block_size = 8
    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm_name}")

    # Extracting IV and HMAC value from the ciphertext 
    iv = ciphertext[:block_size]
    hmac_length = 64 if hash_algorithm == 'SHA512' else 32
    hmac_value = ciphertext[-hmac_length:]
    ciphertext = ciphertext[block_size:-hmac_length]

    # Verifying the HMAC to validate file integrity
    hmac_obj = hmac.HMAC(hmac_key, getattr(hashes, hash_algorithm)(), backend=default_backend())
    hmac_obj.update(iv + ciphertext)
    try:
        hmac_obj.verify(hmac_value)
    except cryptography.exceptions.InvalidSignature:
        raise ValueError("HMAC verification failed. The ciphertext may have been tampered with.")

    # Creating a cipher object with the chosen encryption algorithm
    if algorithm_name.startswith('AES'):
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    else:
        cipher = Cipher(algorithms.TripleDES(encryption_key), modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()

    # Decrypting the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Removing the padding from the decrypted plaintext
    unpadder = padding.PKCS7(cipher.algorithm.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def encrypt_file(input_file, output_file, password, config):
    # Reading plain text data fron input file
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    # Generating a random salt value to create the master key
    salt = os.urandom(16)
    # Determining key length based on the encryption algorithm
    if config['encryption_algorithm'].startswith('AES'):
        key_length = 32
    elif config['encryption_algorithm'] == 'TripleDES':
        key_length = 24
    else:
        raise ValueError(f"Unsupported encryption algorithm: {config['encryption_algorithm']}")
    
    # Deriving master key from the password, salt and the kdf iteration count
    master_key = derive_key(password, salt, config['kdf_iterations'], key_length, config['hash_algorithm'])
    # Deriving the encryption key using the created master key (encryption to encrypt data)
    encryption_key = derive_key(master_key, b'encryption', 1, key_length, config['hash_algorithm'])
    # Deriving the HMAC key using the created master key (HMAC to check integrity of data)
    hmac_key = derive_key(master_key, b'hmac', 1, key_length, config['hash_algorithm'])

    ''' Encrypting the plain text from the input.txt file using the encryption key + encryption algorithm 
    and the HMAC key + hashing algorithm'''
    ciphertext = encrypt_data(plaintext, encryption_key, config['encryption_algorithm'], hmac_key, config['hash_algorithm'])

    # Creating metadata - contains salt, kdf iteration count, hash algorithm and encryption algorithm
    metadata = {
        'encryption_algorithm': config['encryption_algorithm'],
        'hash_algorithm': config['hash_algorithm'],
        'kdf_iterations': config['kdf_iterations'],
        'salt': salt.hex()
    }

    # Writing metadata to the output file, followed by the encrypted cipher text.
    with open(output_file, 'wb') as file:
        file.write(json.dumps(metadata).encode() + b'\n')
        file.write(ciphertext)

def decrypt_file(input_file, password):
    # Reading the encrypted data and meta data from the input file
    with open(input_file, 'rb') as file:
        metadata_json, ciphertext = file.read().split(b'\n', 1)
        metadata = json.loads(metadata_json)

    # Validate metadata
    if not isinstance(metadata, dict) or 'encryption_algorithm' not in metadata \
            or 'hash_algorithm' not in metadata or 'kdf_iterations' not in metadata or 'salt' not in metadata:
        raise ValueError("Invalid metadata found in the input file")

    salt = bytes.fromhex(metadata['salt'])
    # Determining the key length; similar as during encryption of the file.
    if metadata['encryption_algorithm'].startswith('AES'):
        key_length = 32
    elif metadata['encryption_algorithm'] == 'TripleDES':
        key_length = 24
    else:
        raise ValueError(f"Unsupported encryption algorithm: {metadata['encryption_algorithm']}")
    
    # Deriving keys for decryption using the user provided password, salt and meta data
    master_key = derive_key(password, salt, metadata['kdf_iterations'], key_length, metadata['hash_algorithm'])
    encryption_key = derive_key(master_key, b'encryption', 1, key_length, metadata['hash_algorithm'])
    hmac_key = derive_key(master_key, b'hmac', 1, key_length, metadata['hash_algorithm'])

    # Decrypting the ciphertext to obtain plaintext
    plaintext = decrypt_data(ciphertext, encryption_key, metadata['encryption_algorithm'], hmac_key, metadata['hash_algorithm'])

    return plaintext

def measure_kdf_time(iteration_count, password, salt, key_length, hash_algorithm):
    # Calculating the start time of key derivation
    start_time = time.time()
    derive_key(password, salt, iteration_count, key_length, hash_algorithm)
    # Calculating the end time of the key derviation 
    end_time = time.time()
    return end_time - start_time

def best_iteration_count(iteration_counts, password, salt, key_length, hash_algorithm):
    timings = []
    # Iterating according to count provided
    for count in iteration_counts:
        total_time = measure_kdf_time(count, password, salt, key_length, hash_algorithm)
        timings.append((count, total_time))
        print(f"Iteration Count: {count}, Time: {total_time:.3f} seconds")

    # Target time for key derivation; selecting the right count closest to the target
    target_time = 1.0
    closest_count = min(timings, key=lambda x: abs(x[1] - target_time))[0]
    return closest_count

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File Encryption Utility')
    subparsers = parser.add_subparsers(dest='command', help='Choose command (encrypt or decrypt)')

    # Subparsing for the 'encrypt' command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input_file', help='Path to the input file')
    encrypt_parser.add_argument('password', help='Password for encryption')
    encrypt_parser.add_argument('-o', '--output', help='Path to the output file')
    encrypt_parser.add_argument('-c', '--config', help='Path to the configuration file')

    # Subparsing for the 'decrypt' command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input_file', help='Path to the input file')
    decrypt_parser.add_argument('password', help='Password for decryption')
    decrypt_parser.add_argument('-o', '--output', help='Path to the output file')

    args = parser.parse_args()

    if args.command == 'encrypt':
        config = load_config(args.config)
        # Getting the iteration counts from config.json file if it's present, else; the below default counts are considered.
        iteration_counts = config.get('iteration_counts', [10000, 50000, 100000, 500000, 800000, 1000000, 1500000, 2000000])

        password = args.password.encode()
        salt = os.urandom(16)
        key_length = 32 if config['encryption_algorithm'].startswith('AES') else 24
        hash_algorithm = config['hash_algorithm']

        # Passing the created password, salt, key length and hash algorithm for caluculating most efficient iteration count value from the array.
        print("Measuring KDF timings:")
        chosen_count = best_iteration_count(iteration_counts, password, salt, key_length, hash_algorithm)
        print(f"\nChosen Iteration Count: {chosen_count}")

        # Updating the iteration count in the configuration
        config['kdf_iterations'] = chosen_count
        encrypt_file(args.input_file, args.output, args.password.encode(), config)
        print(f"File encrypted successfully. Output file: {args.output}")

    elif args.command == 'decrypt':
        try:
            plaintext = decrypt_file(args.input_file, args.password.encode())
            # Determining the output file name
            output_file = args.output if args.output else 'decrypted_file.txt'
            # Writing the plaintext to the output file
            with open(output_file, 'wb') as file:
                file.write(plaintext)
            print(f"File decrypted successfully. Decrypted content saved to '{output_file}'")
        except (ValueError, KeyError):
            print("Decryption failed. The file may be corrupted/tampered with or password mismatch.")