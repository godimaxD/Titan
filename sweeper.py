import sqlite3
import time
import requests
from tronpy import Tron
from tronpy.keys import PrivateKey
from tronpy.providers import HTTPProvider

# --- CONFIGURATION ---
DB_PATH = "titan.db"
# DESTINATION WALLET: Funds are swept HERE. Change this to YOUR main wallet.
MAIN_WALLET = "TGoTitanMainWalletAddressHereXXXXX" 
TRON_API = "https://api.trongrid.io"

try:
    client = Tron(HTTPProvider(TRON_API))
except:
    print("[!] TRON CLIENT ERROR: Connection failed. Retrying loop...")

print(f">> SWEEPER DAEMON ONLINE.")
print(f">> MONITORING PENDING INVOICES...")

def check_deposits():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cursor = conn.cursor()
        
        # 1. Check for newly assigned wallets (Status='Busy')
        cursor.execute("SELECT address, private_key, assigned_to FROM wallets WHERE status='Busy'")
        busy_wallets = cursor.fetchall()
        
        for addr, priv, dep_id in busy_wallets:
            try:
                # 2. Check Blockchain Balance
                try:
                    # Defensive usage of TronPy
                    trx_bal = float(client.get_account_balance(addr))
                except Exception as api_err:
                    print(f"[-] API Error checking {addr}: {api_err}")
                    continue

                print(f"[*] {addr} | Balance: {trx_bal} TRX | Inv: {dep_id}")
                
                # 3. Match with Deposit Invoice
                cursor.execute("SELECT amount, usd_amount, user_id, status FROM deposits WHERE id=?", (dep_id,))
                deposit_row = cursor.fetchone()
                if not deposit_row: continue
                
                expected_trx, usd_credit, user_id, status = deposit_row
                
                # If invoice expired, wallet should have been freed by Go, but double check status
                if status != 'Pending': continue

                # 4. PAYMENT LOGIC
                # Tolerance of 2% for fluctuation
                if trx_bal >= (expected_trx * 0.98):
                    print(f"\n[$$$] PAYMENT DETECTED on {addr}!")
                    print(f"      User: {user_id} | Crediting: ${usd_credit}")
                    
                    # Update User Balance
                    cursor.execute("UPDATE users SET balance = balance + ? WHERE username=?", (usd_credit, user_id))
                    
                    # Update Deposit Status
                    cursor.execute("UPDATE deposits SET status='Paid' WHERE id=?", (dep_id,))
                    
                    # Sweep Funds (Send to Main Wallet)
                    if trx_bal > 1.1: # Must cover gas
                        try:
                            print(f"      Sweeping to Cold Storage...")
                            # Simple transfer logic. Requires bandwidth/energy or it eats TRX.
                            sweep_amt = int((trx_bal - 0.1) * 1_000_000) # Leave dust for fees
                            txn = client.trx.transfer(MAIN_WALLET, sweep_amt).build().sign(PrivateKey(bytes.fromhex(priv)))
                            txn.broadcast().wait()
                            print("      [+] Sweep Complete.")
                        except Exception as sweep_err: 
                            print(f"      [-] Sweep Failed (Not critical): {sweep_err}")
                    
                    # Free the wallet
                    cursor.execute("UPDATE wallets SET status='Free', assigned_to='' WHERE address=?", (addr,))
                    conn.commit()
                    
            except Exception as loop_err:
                print(f"[-] Loop Error for {addr}: {loop_err}")
        
        conn.close()
    except Exception as db_err:
        print(f"[!] Database Access Error: {db_err}")

# Infinite Surveillance
while True:
    check_deposits()
    time.sleep(5)
