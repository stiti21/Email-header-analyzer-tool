import os
import csv
import mailbox
from email import policy
from email.parser import BytesParser

# ----- PATHS (as you provided) -----
directory_path = "/home/kali/tool/email/phishing_pot"
MBOX_PATH = "/home/kali/tool/email/phishing3.mbox"
csv_file_path = "/home/kali/tool/csv/email_headers.csv"

headers_to_extract = ["From", "To", "Cc", "Date", "Message-ID", "Return-Path", "Authentication-Results"]
limit = 4000
count = 0

os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)

with open(csv_file_path, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["Filename"] + headers_to_extract)
    writer.writeheader()

    # gather .eml file paths (up to limit)
    eml_paths = []
    for root, _, files in os.walk(directory_path):
        for fn in files:
            if fn.lower().endswith(".eml"):
                eml_paths.append(os.path.join(root, fn))
                if len(eml_paths) >= limit:
                    break
        if len(eml_paths) >= limit:
            break

    # parse and write headers for .eml
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
                print(f"Processed {i}/{len(eml_paths)} .eml files")
        except Exception as e:
            print("Error processing .eml:", path, e)
            continue

    print("Finished collecting .eml files. Now processing mbox...")

    # process entire mbox file
    try:
        mbox = mailbox.mbox(MBOX_PATH)
        for j, raw_msg in enumerate(mbox, 1):
            try:
                # get bytes and parse for consistent header extraction
                try:
                    raw_bytes = raw_msg.as_bytes()
                except Exception:
                    raw_bytes = str(raw_msg).encode("utf-8", errors="ignore")
                msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

                filename = f"mbox_msg{j}"
                row = {"Filename": filename}
                for h in headers_to_extract:
                    val = msg.get(h)
                    row[h] = str(val) if val is not None else ""
                writer.writerow(row)
                count += 1
                if j % 500 == 0:
                    print(f"Processed {j} messages from mbox")
            except Exception:
                continue
    except Exception as e:
        print("Error opening/reading mbox:", e)

print("Processed emails:", count)
print("CSV saved to:", csv_file_path)
