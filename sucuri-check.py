import mailbox
import re
import csv
import requests
from email import policy
from email.parser import BytesParser
import os

# ----- CONFIG -----
MBOX_FILE = "/home/kali/tool/email/phishing3.mbox"
OUTPUT_FILE = "/home/kali/tool/csv/link_analysis_mbox.csv"
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# ----- helpers -----
def extract_links(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(errors="ignore")
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")
        except Exception:
            body = ""
    links = re.findall(r"https?://[^\s\"'<>]+", body, flags=re.IGNORECASE)
    return list(dict.fromkeys(links))  # remove duplicates, preserve order

def local_check(url):
    suspicious_words = [
        "login", "verify", "update", "bank", "password",
        "account", "secure", "confirm", "signin", "reset",
        "bit.ly", "tinyurl", "goo.gl"
    ]
    low = url.lower()
    if any(w in low for w in suspicious_words):
        return "Suspicious (Keyword detected)"
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", low):
        return "Suspicious (IP address link)"
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    for t in suspicious_tlds:
        if low.endswith(t) or ("/" in low and ("/" + t.lstrip(".")) in low):
            return "Suspicious (TLD)"
    return "Safe"

def sucuri_check(url):
    try:
        scan_url = f"https://sitecheck.sucuri.net/results/{url}"
        resp = requests.get(scan_url, timeout=10)
        if resp.status_code == 200:
            c = resp.text.lower()
            if "no malware found" in c and "domain clean" in c:
                return "Clean (Sucuri)"
            if "malware" in c or "blacklisted" in c:
                return "Suspicious or Malicious (Sucuri)"
            return "Unclear Result (Sucuri)"
        return f"Sucuri Scan Failed (HTTP {resp.status_code})"
    except Exception as e:
        return f"Sucuri Error: {e}"

# ----- processing mbox -----
results = []
try:
    mbox = mailbox.mbox(MBOX_FILE)
except Exception as e:
    print("Error opening mbox:", e)
    raise SystemExit(1)

for i, raw_msg in enumerate(mbox, start=1):
    # get bytes representation and parse consistently
    try:
        try:
            raw_bytes = raw_msg.as_bytes()
        except Exception:
            raw_bytes = str(raw_msg).encode("utf-8", errors="ignore")
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        continue

    message_id = msg.get("Message-ID") or f"mbox_msg{i}"
    links = extract_links(msg)
    if not links:
        results.append([message_id, "No Links Found", "-", "-"])
        continue

    for link in links:
        local_result = local_check(link)
        if local_result == "Safe":
            sucuri_result = sucuri_check(link)
            mode = "Local + Sucuri"
        else:
            sucuri_result = local_result
            mode = "Local Check Only"
        manual_link = f"https://sitecheck.sucuri.net/results/{link}"
        results.append([message_id, link, mode, sucuri_result, manual_link])

    if i % 500 == 0:
        print(f"Processed {i} messages from mbox")

# ----- write CSV -----
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Message", "URL", "Mode Used", "Result", "Manual_Sucuri_Link"])
    writer.writerows(results)

print("✅ Done! Results saved to:", OUTPUT_FILE)
print("Total messages processed:", len(set(r[0] for r in results)))
print("Total links found:", len([r for r in results if r[1] != "No Links Found"]))
