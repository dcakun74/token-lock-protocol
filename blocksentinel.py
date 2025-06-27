"""
BlockSentinel: мониторинг последних блоков Bitcoin для поиска аномалий.
"""

import requests
import argparse
from time import sleep

def get_latest_blocks(limit=5):
    url = f"https://api.blockchair.com/bitcoin/blocks?q=id(desc)&limit={limit}"
    r = requests.get(url)
    return r.json()["data"]

def get_block_details(block_id):
    url = f"https://api.blockchair.com/bitcoin/raw/block/{block_id}"
    r = requests.get(url)
    return r.json()["data"][str(block_id)]["decoded_raw_block"]

def analyze_block(block):
    txs = block["tx"]
    anomalies = []

    for tx in txs:
        if isinstance(tx, str):
            continue  # skip coinbase hash if abbreviated

        txid = tx.get("txid")
        vout = tx.get("vout", [])
        vin = tx.get("vin", [])

        if len(vout) > 50:
            anomalies.append((txid, f"💣 Слишком много выходов: {len(vout)}"))

        fee = tx.get("fee", 0)
        if fee and fee > 1000000:
            anomalies.append((txid, f"🔥 Высокая комиссия: {fee} сат"))

        for out in vout:
            script = out.get("script_pub_key", {}).get("asm", "")
            if "OP_RETURN" in script:
                anomalies.append((txid, "🧬 Присутствует OP_RETURN"))

            if "v1" in script or "v2" in script:
                anomalies.append((txid, "🧪 Taproot или Witness v1/v2 активность"))

    return anomalies

def sentinel_scan():
    print("🛰️ BlockSentinel: Сканирование последних блоков...
")
    blocks = get_latest_blocks()
    for block in blocks:
        block_id = block["id"]
        print(f"📦 Блок #{block_id}")
        block_data = get_block_details(block_id)
        anomalies = analyze_block(block_data)
        if not anomalies:
            print("  ✅ Без аномалий
")
        else:
            for txid, desc in anomalies:
                print(f"  ⚠️ TX {txid[:10]}...: {desc}")
            print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BlockSentinel — мониторинг аномалий в блоках.")
    args = parser.parse_args()
    sentinel_scan()
