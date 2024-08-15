import os
import hashlib
import random
import sys
import logging
import requests
import time
from dotenv import load_dotenv
from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)

# Constants
LOG_FILE_NAME = "enigmacracker.log"
ENV_FILE_NAME = "EnigmaCracker.env"
WALLETS_FILE_NAME = "wallets_with_balance.txt"
WORDLIST_FILE_NAME = "wordlists.txt"

# Get the absolute path of the directory where the script is located
directory = os.path.dirname(os.path.abspath(__file__))
# Initialize directory paths
log_file_path = os.path.join(directory, LOG_FILE_NAME)
env_file_path = os.path.join(directory, ENV_FILE_NAME)
wallets_file_path = os.path.join(directory, WALLETS_FILE_NAME)
wordlist_file_path = os.path.join(directory, WORDLIST_FILE_NAME)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file_path),  # Log to a file
        logging.StreamHandler(sys.stdout),  # Log to standard output
    ],
)

# Load environment variables from .env file
load_dotenv(env_file_path)

# Environment variable validation
required_env_vars = ["ETHERSCAN_API_KEY"]
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise EnvironmentError(f"Missing environment variables: {', '.join(missing_vars)}")


def load_custom_wordlist():
    # Load the custom wordlist from a file
    with open(wordlist_file_path, 'r') as f:
        wordlist = [line.strip() for line in f]
    return wordlist


def entropy_to_mnemonic(entropy, wordlist):
    """Convert entropy to a mnemonic phrase."""
    if len(entropy) not in (16, 24, 32):
        raise ValueError("Entropy length should be 128, 192, or 256 bits")

    # Compute checksum
    checksum_length = len(entropy) // 4
    checksum = hashlib.sha256(entropy).digest()
    checksum_bits = ''.join([bin(byte)[2:].zfill(8) for byte in checksum])[:checksum_length]

    # Convert entropy and checksum to binary string
    entropy_bits = ''.join([bin(byte)[2:].zfill(8) for byte in entropy])
    mnemonic_bits = entropy_bits + checksum_bits

    # Map binary string to words
    word_indices = [int(mnemonic_bits[i:i+11], 2) for i in range(0, len(mnemonic_bits), 11)]
    mnemonic = ' '.join([wordlist[i] for i in word_indices])

    return mnemonic


def mnemonic_to_seed(mnemonic):
    """Convert mnemonic to seed."""
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    return seed_bytes


def bip44_ETH_wallet_from_seed(seed):
    """Generate an Ethereum wallet from a BIP39 seed."""
    bip44_mst_ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = (
        bip44_mst_ctx.Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    eth_address = bip44_acc_ctx.PublicKey().ToAddress()
    return eth_address


def bip44_BTC_seed_to_address(seed):
    """Generate the Bitcoin address from the seed."""
    bip44_mst_ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)
    btc_address = bip44_addr_ctx.PublicKey().ToAddress()
    return btc_address


def check_ETH_balance(address, etherscan_api_key, retries=3, delay=5):
    """Check the balance of an Ethereum address using Etherscan API."""
    api_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={etherscan_api_key}"

    for attempt in range(retries):
        try:
            response = requests.get(api_url)
            data = response.json()

            if data["status"] == "1":
                balance = int(data["result"]) / 1e18
                return balance
            else:
                logging.error("Error getting balance: %s", data["message"])
                return 0
        except Exception as e:
            if attempt < retries - 1:
                logging.error(f"Error checking balance, retrying in {delay} seconds: {str(e)}")
                time.sleep(delay)
            else:
                logging.error("Error checking balance: %s", str(e))
                return 0


def check_BTC_balance(address, retries=3, delay=5):
    """Check the balance of a Bitcoin address using Blockchain API."""
    for attempt in range(retries):
        try:
            response = requests.get(f"https://blockchain.info/balance?active={address}")
            data = response.json()
            balance = data[address]["final_balance"]
            return balance / 100000000  # Convert satoshi to bitcoin
        except Exception as e:
            if attempt < retries - 1:
                logging.error(f"Error checking balance, retrying in {delay} seconds: {str(e)}")
                time.sleep(delay)
            else:
                logging.error("Error checking balance: %s", str(e))
                return 0


def write_to_file(seed, BTC_address, BTC_balance, ETH_address, ETH_balance):
    """Write the seed, address, and balance to a file in the script's directory."""
    with open(wallets_file_path, "a") as f:
        log_message = f"Seed: {seed}\nAddress: {BTC_address}\nBalance: {BTC_balance} BTC\n\nEthereum Address: {ETH_address}\nBalance: {ETH_balance} ETH\n\n"
        f.write(log_message)
        logging.info(f"Written to file: {log_message}")


def main():
    # Load custom wordlist
    wordlist = load_custom_wordlist()

    try:
        while True:
            entropy = os.urandom(16)  # Generate 128-bit entropy
            mnemonic = entropy_to_mnemonic(entropy, wordlist)
            seed = mnemonic_to_seed(mnemonic)

            # BTC
            btc_address = bip44_BTC_seed_to_address(seed)
            btc_balance = check_BTC_balance(btc_address)

            logging.info(f"Seed: {mnemonic}")
            logging.info(f"BTC address: {btc_address}")
            logging.info(f"BTC balance: {btc_balance} BTC")
            logging.info("")

            # ETH
            eth_address = bip44_ETH_wallet_from_seed(seed)
            etherscan_api_key = os.getenv("ETHERSCAN_API_KEY")
            if not etherscan_api_key:
                raise ValueError("The Etherscan API key must be set in the environment variables.")
            eth_balance = check_ETH_balance(eth_address, etherscan_api_key)
            logging.info(f"ETH address: {eth_address}")
            logging.info(f"ETH balance: {eth_balance} ETH")

            # Check if the address has a balance
            if btc_balance > 0 or eth_balance > 0:
                logging.info("(!) Wallet with balance found!")
                write_to_file(mnemonic, btc_address, btc_balance, eth_address, eth_balance)

    except KeyboardInterrupt:
        logging.info("Program interrupted by user. Exiting...")


if __name__ == "__main__":
    main()
