# Bitcoin Wallet Generator

This Python script generates bitcoin wallets from a mnemonic (or cold-card dice-roll) and derived addresses based on the provided input.

## Installation

1. Clone the repository or download the script file.
2. Install the required libraries by running the following command:

	pip install --no-index --find-links -r requirements.txt

## Usage

1. Fill out config.json
	a. input can be dice-roll (string) or mnemonic (with spaces between each word)
	b. wallet types can be BIP44, BIP49 or BIP84. 
	c. gap limit = number of addresses generated. 
	d. set is_private = True if you do not want to see the WIFs (expose private key on screen). 
