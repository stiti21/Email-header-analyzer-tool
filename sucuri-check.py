import mailbox
import email
import re
import csv
import requests
from email import policy
import os

MBOX_FILE = "/home/kali/tool/email/phishing3.mbox"
OUTPUT_FILE = "/home/kali/tool/csv/link_analysis.csv"
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

def extract_links(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                except:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
        except:
            body = ""
    links = re.findall(r"https?://[^\s\"'.>]+", body)
    return list(set(links))

def local_check(url):
    suspicious_words = ["login", "verify", "update", "bank", "password"]
    if any(word in url.lower() for word in suspicious_words):
        return "Suspicious (Keyword)"
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        return "Suspicious (IP link)"
    return "Safe"

results = []

mbox = mailbox.mbox(MBOX_FILE)
for i, msg in enumerate(mbox, start=1):
    try:
        email_msg = email.message_from_string(msg.as_string(), policy=policy.default)
    except:
        continue

    links = extract_links(email_msg)
    if not links:
        results.append([f"msg_{i}", "No Links Found", "-", "-"])
        continue

    for link in links:
        result = local_check(link)
        results.append([f"msg_{i}", link, "Local Check", result])

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Message", "URL", "Mode Used", "Result"])
    writer.writerows(results)

print(f"✅ Done! Results saved to: {OUTPUT_FILE}")
print(f"Total messages processed: {len(set(r[0] for r in results))}")
print(f"Total links found: {len(results)}")
