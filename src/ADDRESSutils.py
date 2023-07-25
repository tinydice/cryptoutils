from .BIP32utils import *
from .FORMATutils import *
from .COLORutils import green, red

class Address:
    def __init__(self, seed, path, addressType):
        self.path = path
        self.seed = seed
        self.addressType = addressType
        self.root_xprv = extendedKey.parse_from_seed(self.seed)
        self.derived_addr_prv = self.root_xprv.derive_child_xprv(convert_path(self.path))
        self.xprv = self.root_xprv.derive_child_xprv(convert_path(self.path[:-4]))
        self.derived_addr_pub = self.derived_addr_prv.derive_pubkey()  # Added self
        self.xpub = self.xprv.derive_pubkey()  # Added self
        self.private_key = self.derived_addr_prv.key  # Added self
        self.wif = bytes_priv_to_wif(self.private_key)  # Added self
        self.public_key = self.derived_addr_pub.key  # Added self

        if (self.addressType == "P2PKH"):
            self.address = pubkey_to_P2PKH(self.public_key)
            self.verifyResult = green("✔") if (wif_to_P2PKH(self.wif) == self.address) else red("X")
        elif (self.addressType == 'P2WPKH'):
            self.address = pubkey_to_P2SHpP2WPKH(self.public_key)
            self.verifyResult = green("✔") if (wif_to_P2SHpP2WPKH(self.wif) == self.address) else red("X")
        elif (self.addressType == 'bech32'):
            self.address = pubkey_to_bech32(self.public_key)
            self.verifyResult = green("✔") if (wif_to_bech32(self.wif) == self.address) else red("X")

    def spill_address(self, isPrivate=False):  # Added self
        if isPrivate:
            print(f'    {self.path}     {self.address}     {self.verifyResult}')
        else:
            print(f'    {self.path}     {self.address}     {self.wif}     {self.verifyResult}')