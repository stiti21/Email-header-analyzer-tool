import csv
import os
import requests
from datetime import datetime

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.zip', '.gq', '.cf', '.tk', '.ml', '.ga',
    '.info', '.biz', '.club', '.online', '.site', '.website'
}

def extract_domain(email):
    if not email or email == 'N/A':
        return ""
    email = str(email).lower().strip()
    if '@' in email:
        return email.split('@')[1]
    return ""

def has_suspicious_tld(domain):
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

def get_domain_age(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=5)

        if r.status_code != 200:
            return None

        data = r.json()
        events = data.get("events", [])

        for event in events:
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate")
                creation = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return (datetime.utcnow() - creation).days

        return None

    except:
        return None

def analyze(csv_file, output_csv):
    if not os.path.exists(csv_file):
        print("❌ CSV file not found.")
        return

    rows = []
    total = 0
    phishing_total = 0

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            total += 1

            from_field = row.get("From", "")
            domain = extract_domain(from_field)

            bad_tld = has_suspicious_tld(domain)
            age = get_domain_age(domain)

          
            phishing = (
                bad_tld or 
                (age is not None and age < 30) or
                (age is None)  # treat unknown domain age as suspicious
            )

            if phishing:
                phishing_total += 1

            rows.append({
                "Filename": row.get("Filename", "N/A"),
                "Extracted_Domain": domain,
                "Suspicious_TLD": bad_tld,
                "Domain_Age_Days": age if age else "Unknown",
                "Phishing": "YES" if phishing else "NO"
            })

            if total % 30 == 0:
                print(f"📌 Processed {total} emails...")

    fieldnames = ["Filename", "Extracted_Domain", "Suspicious_TLD", "Domain_Age_Days", "Phishing"]

    with open(output_csv, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("\n✅ DONE!")
    print(f"📨 Total emails processed: {total}")
    print(f"🚨 Total phishing emails: {phishing_total}")
    print(f"📊 Phishing rate: {phishing_total / total * 100:.2f}%")
    print(f"📄 Output saved at: {output_csv}")

if __name__ == "__main__":
    analyze(
        "/home/stiti/test/csv/email_headers.csv",
        "/home/stiti/test/csv/email_phishing.csv"
    )

