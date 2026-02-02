import sqlite3
from tronpy.keys import PrivateKey
import os

DB_PATH = "titan.db"

print(f"[*] Accessing Treasury: {DB_PATH}...")

if not os.path.exists(DB_PATH):
    # Just in case DB is missing, create simple placeholder
    print("[-] WARNING: titan.db not found! Creating...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS wallets (address TEXT PRIMARY KEY, private_key TEXT, status TEXT, assigned_to TEXT)')
    conn.commit()
    conn.close()

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Create table if missing
cursor.execute('CREATE TABLE IF NOT EXISTS wallets (address TEXT PRIMARY KEY, private_key TEXT, status TEXT, assigned_to TEXT)')

print("[*] Manufacturing 50 Fresh TRC20 Wallets...")
count = 0

for i in range(50):
    try:
        # Generates REAL keys. Not fake junk.
        priv = PrivateKey.random()
        addr = priv.public_key.to_base58check_address()
        priv_hex = priv.hex()
        
        cursor.execute("SELECT 1 FROM wallets WHERE address=?", (addr,))
        if cursor.fetchone(): continue
        
        # Inject as 'Free' for the Go Server to consume
        cursor.execute("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES (?, ?, 'Free', '')", (addr, priv_hex))
            
        print(f"[+] Forged Wallet: {addr}")
        count += 1
    except Exception as e:
        print(f"[-] Error: {e}")

conn.commit()
conn.close()
print(f"\n[SUCCESS] {count} Wallets Loaded into the Matrix.")
