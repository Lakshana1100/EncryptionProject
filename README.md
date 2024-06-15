# EncryptionProject

To encrypt - python3 main.py encrypt input.txt passwordhehehe -o encrypted_file.txt
To decrypt - python3 main.py decrypt encrypted_file.txt passwordhehehe -o decrypted_file.txt
User must provide content to be encrypted in the input.txt file
User must select enryption algorithm and hash algorithm in the config.json file
Example :
{
  "encryption_algorithm": "AES128",
  "hash_algorithm": "SHA256",
  "iteration_counts": [10000, 50000, 100000, 500000, 800000, 1000000, 1500000, 2000000]
}
Encryption Algo choices : AES128, AES256, 3DES
Hash Algo choices : SHA256, SHA512
