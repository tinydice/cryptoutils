from BIP32utils import extendedKey
from keymath import *
import json
from COLORutils import green, red

with open('info.json', 'r') as file:
    info = json.load(file)
    input = info['input']
    word_count = info['word_count']
    passphrase = info['passphrase']
    ACCOUNT_PATH = convert_path(info['account'])
    CHILD_PATHS = info['children']

if input[-1].isdigit():
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
    private_key = derived_addr0_prv.key.hex()
    wif = hex_prv_to_wif(private_key)
    print(f'wif = {wif}')
    public_key = derived_addr0_pub.key.hex()
    public_address = hex_pub_to_addr(public_key)
    print(f'apub = {public_address}\n')

    # Validate wallet address by converting wif to public address
    if wif_to_addr(wif) == public_address:
        print(green("#########################################"))
        print(green("#              Valid Address            #"))
        print(green("#########################################"))
    else:
        print(red("#########################################"))
        print(red("#               WARNING:                #"))
        print(red("#    WIF DOES NOT MATCH PUBLIC KEY      #"))
        print(red("#########################################"))






