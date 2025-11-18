import mailbox
import re
import csv
import requests
from email import policy
from email.parser import BytesParser
import os
import base64
import time

# CONFIGURATION
MBOX_FILE = "/home/kali/tool/email/phishing3.mbox"
OUTPUT_FILE = "/home/kali/tool/csv/virus_total_link_analysis.csv"
VT_API_KEY = "YOUR_API_KEY_HERE"  

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

VT_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {"x-apikey": VT_API_KEY}


# EXTRACT LINKS FROM EMAIL BODY
def extract_links(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(errors="ignore")
                except:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")
        except:
            body = ""
    links = re.findall(r"https?://[^\s\"'<>]+", body, flags=re.IGNORECASE)
    return list(dict.fromkeys(links)) 

# SIMPLE LOCAL CHECK
def local_check(url):
    low = url.lower()

    suspicious_words = ["login", "verify", "bank","account"," reset","signin","PIN","credit card", "secure",  "password", "update"]
    if any(w in low for w in suspicious_words):
        return "Suspicious (Keyword)"

    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", low):
        return "Suspicious (IP Link)"

    return "Safe"

# VIRUSTOTAL URL CHECK
def vt_check(url):
    try:
        resp = requests.post(
            VT_SCAN_URL,
            headers=VT_HEADERS,
            data={"url": url},
            timeout=15
        )

        data = resp.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return "VT Error: No analysis ID"

        time.sleep(1)

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=VT_HEADERS,
            timeout=15
        ).json()

        stats = result.get("data", {}).get("attributes", {}).get("stats", {})

        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)

        if mal > 0:
            return f"Malicious ({mal} engines)"
        if sus > 0:
            return f"Suspicious ({sus} engines)"
        if harm > 0:
            return "Clean"

        return "Unknown"

    except Exception as e:
        return f"VT Error: {e}"

# PROCESS MBOX FILE

results = []

mbox = mailbox.mbox(MBOX_FILE)

for i, raw_msg in enumerate(mbox, start=1):
    try:
        raw_bytes = raw_msg.as_bytes()
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except:
        continue

    message_id = msg.get("Message-ID") or f"msg_{i}"
    links = extract_links(msg)

    if not links:
        results.append([message_id, "No Links Found", "-", "-", "-"])
        continue

    for link in links:
        local_result = local_check(link)
        vt_result = vt_check(link)
        vt_link = vt_gui_link(link)

        results.append([message_id, link, local_result, vt_result, vt_link])

    if i % 500 == 0:
        print(f"Processed {i} messages from mbox...")

# SAVE CSV OUTPUT

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Message_ID", "URL", "Local_Check", "VT_Result", "VT_GUI_Link"])
    writer.writerows(results)

print("Done! Results saved to:", OUTPUT_FILE)
print("Total messages processed:", len(set(r[0] for r in results)))
print("Total links found:", len([r for r in results if r[1] != "No Links Found"]))
