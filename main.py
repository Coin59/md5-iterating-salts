import hashlib
import argparse

def generate_hash(algorithm, password, salt):
    if algorithm == 'md5':
        hash_obj = hashlib.md5()
    elif algorithm == 'sha1':
        hash_obj = hashlib.sha1()
    elif algorithm == 'sha256':
        hash_obj = hashlib.sha256()
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512()
    else:
        print("Unsupported or invalid algorithm selected.")
        return None
    
    salted_password = ''
    for i, char in enumerate(password):
        salted_password += char + salt[i % len(salt)]
    
    salted_password_bytes = salted_password.encode('utf-8')
    hash_obj.update(salted_password_bytes)
    hash_value = hash_obj.hexdigest()
    return hash_value

# argument parser creation
parser = argparse.ArgumentParser(description='Hash a password with salt.')
parser.add_argument('-p', '--password', type=str, help='The password to hash.', required=True)
parser.add_argument('-s', '--salt', type=str, help='The salt to use.', required=True)
parser.add_argument('-a', '--algorithm', type=str, help='The hashing algorithm (md5, sha1, sha256, sha512).', required=True)

# argument parsing
args = parser.parse_args()
password = args.password
salt = args.salt
algorithm = args.algorithm.lower()

# hash generation
hashed_password = generate_hash(algorithm, password, salt)

if hashed_password:
    print("Hash:", hashed_password + ":" + salt)
