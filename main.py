#!/usr/bin/env python3

import mailbox
import email
import re
import csv
from email.header import decode_header
from urllib.parse import urlparse
import html

MBOX_PATH = "/home/kali/tool/email/phishing3.mbox"
OUTPUT_CSV = "/home/kali/tool/csv/phish_results.csv"

# ------------------- RULES CONFIG -------------------
SUSPICIOUS_WORDS = [
    "verify", "update", "urgent", "suspended", "reset", "confirm",
    "security alert", "unusual activity", "account locked", "billing issue"
]

SHORTENERS = ("bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly")

DOMAIN_RE = re.compile(
    r'\b((?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}|xn--[a-z0-9-]+|\d{1,3}(?:\.\d{1,3}){3})\b',
    re.IGNORECASE
)

ANCHOR_RE = re.compile(
    r'<a\s+[^>]*href\s*=\s*"(.*?)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)

AREA_RE = re.compile(
    r'<area\s+[^>]*href\s*=\s*"(.*?)"[^>]*>',
    re.IGNORECASE | re.DOTALL
)

# ------------------- DECODERS -------------------
def decode_header_value(value):
    if not value:
        return ""
    try:
        decoded = decode_header(value)
        final = ""
        for part, enc in decoded:
            if isinstance(part, bytes):
                final += part.decode(enc or "utf-8", errors="ignore")
            else:
                final += part
        return final
    except:
        return str(value)

# ------------------- HELPERS -------------------
def extract_domain_from_url(url):
    try:
        p = urlparse(url)
        netloc = p.netloc or p.path
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        return (netloc or "").lower()
    except:
        return ""

def extract_domain_from_text(text):
    t = html.unescape(text).strip()
    m = DOMAIN_RE.search(t)
    return m.group(1).lower() if m else ""

def find_links(html_body):
    anchors = []
    for m in ANCHOR_RE.finditer(html_body):
        href = html.unescape(m.group(1).strip())
        display = re.sub('<.*?>', '', m.group(2)).strip()
        anchors.append((href, display))
    areas = AREA_RE.findall(html_body)
    return anchors, areas

# ------------------- MAIN ANALYSIS -------------------
def analyze_message(msg):
    msg_id = decode_header_value(msg.get("Message-ID",""))
    date = decode_header_value(msg.get("Date",""))
    from_addr = decode_header_value(msg.get("From",""))
    to_addr = decode_header_value(msg.get("To",""))
    subject = decode_header_value(msg.get("Subject",""))

    result = {
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "phishing_flag": False,
        "reasons": [],
        "urls_found": ""
    }

    # Extract HTML
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                    break
    else:
        if msg.get_content_type() == "text/html":
            payload = msg.get_payload(decode=True)
            if payload:
                html_body = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")

    urls = []

    if html_body:

        anchors, areas = find_links(html_body)

        # -------- RULE 1: Check suspicious keywords in subject --------
        for word in SUSPICIOUS_WORDS:
            if word in subject.lower():
                result["phishing_flag"] = True
                result["reasons"].append(f"suspicious keyword: {word}")

        # -------- RULE 2: Anchor tag mismatch (visible vs actual URL) --------
        for href, display in anchors:
            urls.append(href)
            href_domain = extract_domain_from_url(href)
            disp_domain = extract_domain_from_text(display)

            if disp_domain and href_domain and disp_domain != href_domain:
                result["phishing_flag"] = True
                result["reasons"].append(
                    f"display domain '{disp_domain}' != href domain '{href_domain}'"
                )

        # -------- RULE 3: Detect URL shorteners --------
            for s in SHORTENERS:
                if s in href_domain:
                    result["phishing_flag"] = True
                    result["reasons"].append(f"shortened URL used: {s}")
                    break

        # -------- RULE 4: Numeric IP in link --------
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", href_domain):
                result["phishing_flag"] = True
                result["reasons"].append("numeric IP used in link")

        # -------- RULE 5: Punycode domains (IDN homograph attacks) --------
            if href_domain.startswith("xn--"):
                result["phishing_flag"] = True
                result["reasons"].append("punycode domain in link")

        # -------- RULE 6: Image map with suspicious URL --------
        for area in areas:
            urls.append(area)
            if re.match(r"^http://\d{1,3}(\.\d{1,3}){3}", area):
                result["phishing_flag"] = True
                result["reasons"].append("image-map link uses numeric IP")

    result["urls_found"] = ";".join(urls)
    result["reasons"] = ";".join(dict.fromkeys(result["reasons"]))

    return result

# ------------------- SCAN MBOX -------------------
def process_mbox():
    mbox = mailbox.mbox(MBOX_PATH)
    fieldnames = ["from","to","subject","phishing_flag","reasons","urls_found"]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for msg in mbox:
            try:
                email_msg = email.message_from_bytes(msg.as_bytes())
            except:
                continue

            res = analyze_message(email_msg)
            writer.writerow(res)

    print("Done. Results saved to:", OUTPUT_CSV)

if __name__ == "__main__":
    process_mbox()
