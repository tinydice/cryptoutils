from BIP39utils import *
import os
import json
from Wallet import *
from enum import Enum

class seedType(Enum):
    DICE_ROLL = 1
    MNEMONIC = 2

BIP44_PATH = "m/44'/0'/0'/"
BIP49_PATH = "m/49'/0'/0'/"
BIP84_PATH = "m/84'/0'/0'/"

class BitcoinAccount:
    def __init__(self, jsonName='config.json'):
        self.jsonName = jsonName
        if not jsonName.endswith('.json'):
            self.jsonName += '.json'
        with open(self.jsonName, 'r') as file:
            self.info = json.load(file)
        self.input = self.info['input']
        self.word_count = self.info['word_count']
        self.passphrase = self.info['passphrase']
        self.walletTypes = self.info['wallet_types']
        self.walletTypes = [self.walletTypes] if isinstance(self.walletTypes, str) else self.walletTypes

        if self.input == "":
            self.seedType = seedType.DICE_ROLL
            rolls = []
            for _ in range(100):
                roll = int.from_bytes(os.urandom(1), "big") % 6 + 1
                rolls.append(str(roll))

            self.diceRoll = ''.join(rolls)
            self.entropyHash = sha256(self.diceRoll.encode("utf-8"))
            self.mnemonic = get_mnemonic(self.entropyHash, self.word_count)

        elif self.input[-1].isdigit():
            self.seedType = seedType.DICE_ROLL
            self.diceRoll = self.input
            self.entropyHash = sha256(self.diceRoll.encode("utf-8"))
            self.mnemonic = get_mnemonic(self.entropyHash, self.word_count)

        elif self.input[-1].isalpha():
            self.seedType = seedType.MNEMONIC
            self.diceRoll = None
            self.entropyHash = None
            self.mnemonic = self.input

        self.seed = get_seed(self.mnemonic.encode('utf-8'), self.passphrase)

        self.wallets = []
        self.gapLimit = self.info['gap_limit']

        for walletType in self.walletTypes:
            if (walletType == 'BIP44'):
                self.path = BIP44_PATH
                self.addressType = 'P2PKH'
            elif (walletType == 'BIP49'):
                self.path = BIP49_PATH
                self.addressType = 'P2WPKH'
            elif (walletType == 'BIP84'):
                self.path = BIP84_PATH
                self.addressType = 'bech32'

            self.wallets.append(Wallet(self.seed, self.addressType, self.path, self.gapLimit))

    def spillAddresses(self, isPrivate=True):
        print(f'Mnemonic:')
        print(f"    {self.mnemonic} {self.passphrase}")
        for i in range(len(self.wallets)) :
            wallet_type = self.walletTypes[i]
            print(f'Addresses:         ({wallet_type})')
            for address in self.wallets[i].addresses:
                address.spill_address(isPrivate)
            print(f'Change Addresses:  ({wallet_type})')
            for changeAddress in self.wallets[i].changeAddresses:
                changeAddress.spill_address(isPrivate)
def main():
    account = BitcoinAccount()
    account.spillAddresses(False)

if __name__ == "__main__":
    main()
