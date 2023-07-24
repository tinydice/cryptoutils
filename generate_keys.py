from BIP32utils import *
from BIP39utils import *
from ECCutils import *
from WALLETutils import *
from COLORutils import green, red
import os
import json

with open('oldjson/info2.json', 'r') as file:
    info = json.load(file)
    input = info['input']
    word_count = info['word_count']
    passphrase = info['passphrase']
    ACCOUNT_PATH = convert_path(info['account'])
    CHILD_PATHS = info['children']
    ADDRESS_TYPE = info['address_type']

if input == "":
    rolls = []
    for _ in range(100):
        roll = int.from_bytes(os.urandom(1), "big") % 6 + 1
        rolls.append(str(roll))

    diceRoll = ''.join(rolls)
    print(diceRoll)
    entropyHash = sha256(diceRoll.encode("utf-8"))
    mnemonic = get_mnemonic(entropyHash, word_count)
    print(f'Dice-Roll: {diceRoll}')

elif input[-1].isdigit():
    diceRoll = input
    entropyHash = sha256(diceRoll.encode("utf-8"))
    mnemonic = get_mnemonic(entropyHash, word_count)
    print(f'Dice-Roll: {diceRoll}')

elif input[-1].isalpha():
    mnemonic = input



print(f'BIP39 Mnemonic: {mnemonic}')
print(f'BIP39 Passphrase: {passphrase}')
wallet_seed = get_seed(mnemonic.encode('utf-8'), passphrase)
root_xprv = extendedKey.parse_from_seed(wallet_seed)
print(f'BIP39 seed: {wallet_seed.hex()}')
print(f'BIP32 Root Key = {root_xprv.serialize()}\n')
child_xprv = root_xprv.derive_child_xprv(ACCOUNT_PATH)
child_xpub = child_xprv.derive_pubkey()
print(f"ACCOUNT PATH = {derivation_path_string(ACCOUNT_PATH)}")
print(f'BIP44 ACCOUNT xprv = {child_xprv.serialize()}')
print(f'BIP44 ACCOUNT xpub = {child_xpub.serialize()}\n')

for PATH in CHILD_PATHS:
    PATH = convert_path(info['account'] + PATH)
    derived_addr0_prv = root_xprv.derive_child_xprv(PATH)
    derived_addr0_pub = derived_addr0_prv.derive_pubkey()
    print(f"WALLET PATH = {derivation_path_string(PATH)}")
    private_key = derived_addr0_prv.key
    print(f'private_key = {private_key.hex()}')
    wif = bytes_priv_to_wif(private_key)
    print(f'wif = {wif}')
    public_key = derived_addr0_pub.key
    print(f'public_key = {public_key.hex()}')
    P2PKH = pubkey_to_P2PKH(public_key)
    print(f'P2PKH = {P2PKH}')

    # P2SHpP2WPKH IS m/49'/...
    P2SHpP2WPKH = pubkey_to_P2SHpP2WPKH(public_key)
    print(f'P2SH-P2WPKH = {P2SHpP2WPKH}')
    # P2SHpP2WSH = pubkey_to_P2SHpP2WSH(public_key)
    # print(f'P2SH-P2WSH = {P2SHpP2WSH}')
    # BECH32 IS m/84'/...
    bech32 = pubkey_to_bech32(public_key)
    print(f'bech32 = {bech32}')

    # Validate wallet address by converting wif to public address
    if (ADDRESS_TYPE == 'P2PKH'):
        if wif_to_P2PKH(wif) == P2PKH:
            print(green("#########################################"))
            print(green("#              Valid Address            #"))
            print(green("#########################################"))
        else:
            print(red("#########################################"))
            print(red("#               WARNING:                #"))
            print(red("#    WIF DOES NOT MATCH PUBLIC KEY      #"))
            print(red("#########################################"))



