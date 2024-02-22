import os
import random
import time
import pandas as pd
import requests
import json
from web3 import Web3, HTTPProvider
from eth_account import Account
from nugger import setup_gay_logger

# Constants and configurations
ABI_FILE_PATH = 'abi.json'
RPC_URL = 'https://rpc.zora.energy'
EXCEL_PATH = 'data.xlsx'
MIN_TRANSACTION_DELAY = 15000
MAX_TRANSACTION_DELAY = 30000
SHUFFLE_ACCOUNTS = True

with open(ABI_FILE_PATH, 'r') as abi_file:
    contract_abi = json.load(abi_file)

w3 = Web3(HTTPProvider(RPC_URL))

def read_file_lines(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def create_excel_file(file_path):
    private_keys = read_file_lines('pkey.txt')
    proxies = read_file_lines('proxies.txt')
    proxies_extended = proxies * (len(private_keys) // len(proxies)) + proxies[:len(private_keys) % len(proxies)]
    df = pd.DataFrame({'Private_Key': private_keys, 'Proxy': proxies_extended})
    df.to_excel(file_path, index=False)

def mint_token(logger, private_key, proxy=None):
    local_account = Account.from_key(private_key)
    sender_address = w3.to_checksum_address(local_account.address)
    normalized_address = sender_address.lower().strip("0x")
    num_zeros_needed = 66 - len(normalized_address) - 2  # Adjust for '0x'
    formatted_address = "0" * num_zeros_needed + normalized_address
    formatted_address_bytes = bytes.fromhex(formatted_address)

    try:
        session = requests.Session()
        if proxy:
            credentials, ip_port = proxy.split('@')
            session.proxies = {"http": f"http://{credentials}@{ip_port}", "https": f"http://{credentials}@{ip_port}"}
        w3.provider = HTTPProvider(RPC_URL, session=session)
        contract_address = w3.to_checksum_address("0x7E8f28A51471A9A434505aC58Ded39c422e73028")
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)

        ether_amount = 0.000777
        wei_amount = ether_amount * 10 ** 18
        rounded_value = round(random.uniform(0.001, 0.005), 4)
        txm = contract.functions.mintWithRewards(
            w3.to_checksum_address("0x04e2516a2c207e84a1839755675dfd8ef6302f0a"),
            1,
            1,
            formatted_address_bytes,
            w3.to_checksum_address("0x32eb30cae36e1c2e9271ca1c02da64e5c27cb465")
        ).build_transaction({
            'value': int(wei_amount),
            'gas': 180000,
            'maxPriorityFeePerGas': int(w3.to_wei(rounded_value, 'gwei')),
            'maxFeePerGas': int(w3.to_wei(rounded_value, 'gwei')),
            'nonce': w3.eth.get_transaction_count(sender_address),
            'chainId': 7777777
        })

        signed_txn = w3.eth.account.sign_transaction(txm, private_key)
        txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(txn_hash)

        if receipt['status'] == 1:
            logger.info(f"Transaction successfully completed: https://explorer.zora.energy/tx/{txn_hash.hex()}")
            with open("successful_tx.txt", "a") as f:
                f.write(f"Address {sender_address} | https://explorer.zora.energy/tx/{txn_hash.hex()}\n")
            return True
        else:
            logger.warning(f"Transaction was unsuccessful: https://explorer.zora.energy/tx/{txn_hash.hex()}")
            with open("failed_tx.txt", "a") as f:
                f.write(f"Address {sender_address} | https://explorer.zora.energy/tx/{txn_hash.hex()}\n")
            return False
    except Exception as e:
        logger.error(f"Error processing wallet {sender_address}: {e}")
        return False

if not os.path.exists(EXCEL_PATH):
    create_excel_file(EXCEL_PATH)

def main():
    df = pd.read_excel(EXCEL_PATH)
    private_keys = df['Private_Key'].tolist()
    proxies_list = df['Proxy'].tolist()
    all_indices = list(range(len(private_keys)))

    if SHUFFLE_ACCOUNTS:
        random.shuffle(all_indices)

    for idx in all_indices:
        private_key = private_keys[idx]
        proxy = proxies_list[idx]
        logger = setup_gay_logger(Account.from_key(private_key).address)

        try:
            if mint_token(logger, private_key, proxy):
                df.drop(idx, inplace=True)
                df.to_excel(EXCEL_PATH, index=False)
            else:
                logger.info("Token minting unsuccessful. Waiting before retrying...")
                time.sleep(10)
                continue
        except Exception as e:
            logger.error(f"Exception occurred: {e}. Waiting before retrying...")
            time.sleep(10)
            continue

        delay = random.randint(MIN_TRANSACTION_DELAY, MAX_TRANSACTION_DELAY)
        logger.info(f"Waiting {delay} seconds before the next mint...")
        time.sleep(delay)

if __name__=="__main__":
    main()