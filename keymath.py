"""This module contains BIP39 helper functions"""

import hashlib
from BIP39utils import *
from ECCutils import PrivateKey

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def convert_path(path_string):
    components = path_string.split('/')[1:]  # Split the string and remove the leading 'm'

    path = []
    for component in components:
        if "'" in component:
            index = int(component.replace("'", ""))
            path.append((index, True))
        else:
            index = int(component)
            path.append((index, False))

    return path

def hex_pub_to_addr(hex_pub):
    hex_key_bytes = bytes.fromhex(hex_pub)
    key_bytes = b'\x00' + hash160(hex_key_bytes)
    return encode_base58_checksum(key_bytes)

def hex_prv_to_wif(hex_prv):
    hex_k_bytes = bytes.fromhex(hex_prv)
    key_bytes = b'\x80' + hex_k_bytes + b'\x01' # Always compressed
    return encode_base58_checksum(key_bytes)

def wif_to_hex_prv(wif):
    hex_wif = hex(int.from_bytes(decode_base58(wif), 'big'))[3:-6]
    hex_prv = hex_wif[1:-4]
    return hex_prv

def wif_to_addr(wif):
    hex_prv = wif_to_hex_prv(wif)
    private_key = bytes.fromhex(hex_prv)
    public_key = get_pubkey(private_key)
    public_address = hex_pub_to_addr(public_key.hex())
    return public_address

def get_seed(mnemonic_bytes, passphrase=None):
    """
    This function creates a mnemonic seed from bytes encoded mnemonic.
    Passphrase is optional
    """

    salt = ("mnemonic" + passphrase).encode("utf8")
    seed = hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt, 2048, )
    return seed

def get_pubkey(private_key_bytes):
    """
    This function returns SEC encoded public key from byte-encoded private key
    """
    secret = int.from_bytes(private_key_bytes, "big")
    private_key = PrivateKey(secret)
    public_key = private_key.point
    return public_key.sec(compressed=True)

def derivation_path_string(path, private=True):
    """
    This function returns a string friendly version of the derivation path
    """
    if private:
        result = "m"
    else:
        result = "M"
    for item in path:
        result += "/"
        index, hardened = item
        if hardened:
            result += str(index) + "'"
        else:
            result += str(index)
    return result

def decode_base58(base58_string):
    """
    This function decodes a base58 string to a number
    """
    num = 0
    for char in base58_string:
        num *= 58
        num += BASE58_ALPHABET.index(char)

    return num.to_bytes(82, byteorder='big')

def encode_base58(data):
    """
    This function encodes bytes to a base58 string
    """
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(data, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def encode_base58_checksum(data):
    """
    This function returns the Base58 check format
    """
    return encode_base58(data + hash256(data)[:4])

def hash160(data):
    """sha256 followed by ripemd160"""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def hash256(data):
    """two rounds of sha256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def sha256(data):
    """one round of sha256"""
    return hashlib.sha256(data).digest()
