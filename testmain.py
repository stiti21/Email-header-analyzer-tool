import os
import csv
from email import policy
from email.parser import BytesParser

directory_path = "/home/stiti/solaf/emails/phishing_pot/email"
headers_to_extract = ["From", "To", "Cc", "Date", "Message-ID", "Return-Path", "Authentication-Results"]
csv_file_path = "/home/stiti/email_headers.csv"

limit = 4000
count = 0

with open(csv_file_path, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["Filename"] + headers_to_extract)
    writer.writeheader()

    # gather .eml file paths
    eml_paths = []
    for root, _, files in os.walk(directory_path):
        for fn in files:
            if fn.lower().endswith(".eml"):
                eml_paths.append(os.path.join(root, fn))
                if len(eml_paths) >= limit:
                    break
        if len(eml_paths) >= limit:
            break

    for i, path in enumerate(eml_paths, 1):
        try:
            with open(path, "rb") as f:
                raw = f.read()
            if not raw or len(raw) < 80:
                continue
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            row = {"Filename": os.path.basename(path)}
            for h in headers_to_extract:
                val = msg.get(h)
                row[h] = str(val) if val is not None else ""
            writer.writerow(row)
            count += 1
            if i % 500 == 0:
                print(f"Processed {i}/{len(eml_paths)}")
        except Exception:
            continue

print("Processed emails:", count)
