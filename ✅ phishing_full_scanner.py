#!/usr/bin/env python3
import mailbox
import email
import re
import csv
from bs4 import BeautifulSoup
from urllib.parse import urljoin

MBOX_FILE = "/home/kali/tool/email/phishing3.mbox"
OUTPUT_CSV = "/home/kali/tool/csv/phishing_results.csv"

# Regex for URLs
URL_RE = re.compile(r'https?://[^\s"]+')

# كلمات مشبوهة
SUSPICIOUS_WORDS = [
    "login", "log in", "password", "pass", "verify", "verification",
    "reset", "update", "urgent", "bank", "account", "security",
    "confirm", "click", "unlock", "suspend", "locked"
]

def contains_suspicious_words(text):
    text_l = text.lower()
    for word in SUSPICIOUS_WORDS:
        if word in text_l:
            return True
    return False


def extract_links_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    links = []

    # --------- <a href="..."> ---------- #
    for a in soup.find_all("a", href=True):
        visible = a.get_text(strip=True)
        actual = a["href"]
        links.append((visible, actual))

    # --------- <img src="..."> ---------- #
    for img in soup.find_all("img"):
        src = img.get("src", "").strip()
        href = None

        # إذا الصورة داخل <a>
        parent = img.find_parent("a")
        if parent and parent.get("href"):
            href = parent["href"]

        # إذا ما في href، نستعمل src كرابط
        if src:
            visible = "[IMAGE]"
            actual = href if href else src
            links.append((visible, actual))

    return links


def extract_links_from_text(text):
    return [(m, m) for m in URL_RE.findall(text)]


def check_if_phishing(visible, actual):
    # mismatch visible vs actual
    if visible.strip().lower() != actual.strip().lower() and visible != "[IMAGE]":
        return True  
    return False


def process_message(msg):
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except:
                payload = None

            if not payload:
                continue

            try:
                decoded = payload.decode(errors="ignore")
            except:
                continue

            if content_type == "text/plain":
                body_text += decoded
            elif content_type == "text/html":
                body_html += decoded
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode(errors="ignore")

    links = []

    if body_html:
        links.extend(extract_links_from_html(body_html))

    if body_text:
        links.extend(extract_links_from_text(body_text))

    return links, body_text + " " + body_html


def main():
    mbox = mailbox.mbox(MBOX_FILE)

    total_emails = 0
    phishing_emails = 0

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email_id", "from", "subject", "visible_url", "actual_url", "is_phishing", "reason"])

        for idx, msg in enumerate(mbox, start=1):
            total_emails += 1

            subject = msg["subject"]
            sender = msg["from"]

            links, full_text = process_message(msg)

            email_is_phishing = False
            suspicious_reason = ""

            # --------- check suspicious words --------- #
            if contains_suspicious_words(full_text):
                email_is_phishing = True
                suspicious_reason = "suspicious_words"

            if not links:
                writer.writerow([idx, sender, subject, "", "", "no", "no_links"])
            else:
                for visible, actual in links:
                    phishing = check_if_phishing(visible, actual)

                    reason = ""
                    if phishing:
                        reason = "link_mismatch"
                    if suspicious_reason:
                        reason += f" | {suspicious_reason}"

                    if phishing or suspicious_reason:
                        email_is_phishing = True

                    writer.writerow([idx, sender, subject, visible, actual,
                                     "yes" if (phishing or suspicious_reason) else "no", reason])

            if email_is_phishing:
                phishing_emails += 1

    print(f"[+] Done! Results saved to: {OUTPUT_CSV}")
    print(f"[+] Total emails scanned: {total_emails}")
    print(f"[+] Emails containing phishing: {phishing_emails}")


if __name__ == "__main__":
    main()
