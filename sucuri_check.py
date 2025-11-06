import os
import email
import re
import csv
import requests
from email import policy

EMAIL_FOLDER = "/home/stiti/tool/dataset/emails"
OUTPUT_FILE = "/home/stiti/tool/csv/link_analysis.csv"

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
        return "Suspicious (Keyword detected)"
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        return "Suspicious (IP address link)"
    return "Safe"

def sucuri_check(url):
    try:
        scan_url = f"https://sitecheck.sucuri.net/results/{url}"
        response = requests.get(scan_url, timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            if "no malware found" in content and "domain clean" in content:
                return "Clean (Sucuri)"
            elif "malware" in content or "blacklisted" in content:
                return "Suspicious or Malicious (Sucuri)"
            else:
                return "Unclear Result (Sucuri)"
        else:
            return "Sucuri Scan Failed"
    except Exception as e:
        return f"Sucuri Error: {str(e)}"

def main():
    results = []
    for root, _, files in os.walk(EMAIL_FOLDER):
        for file in files:
            if not file.endswith(".eml"):
                continue
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    msg = email.message_from_file(f, policy=policy.default)
            except:
                continue
            links = extract_links(msg)
            if not links:
                results.append([file, "No Links Found", "-", "-", "-"])
                continue
            for link in links:
                result = sucuri_check(link)
                mode = "Sucuri SiteCheck"
                manual_link = f"https://sitecheck.sucuri.net/results/{link}"
                results.append([file, link, mode, result, manual_link])
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["File", "URL", "Mode Used", "Result", "Manual_Sucuri_Link"])
        writer.writerows(results)
    print(f"✅ Done! Results saved in → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
