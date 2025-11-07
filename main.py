import os
import email
from email import policy
import mailbox
import csv

directory_path = "/home/kali/tool/"
headers_to_extract = ["From", "To", "Cc", "Date", "Message-ID", "Return-Path", "Authentication-Results"]
csv_file_path = "/home/kali/tool/email_headers.csv"

file_counts = {}
total_emails = 0

with open(csv_file_path, mode="w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["Source_File"] + headers_to_extract)
    writer.writeheader()

    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            if filename.startswith("."):
                continue
            filepath = os.path.join(root, filename)
            try:
                if filename.lower().endswith(".eml"):
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        msg = email.message_from_file(f, policy=policy.default)
                    row = {"Source_File": filename}
                    for h in headers_to_extract:
                        val = msg.get(h, "")
                        if isinstance(val, bytes):
                            try:
                                val = val.decode("utf-8", errors="ignore")
                            except:
                                val = str(val)
                        row[h] = val
                    writer.writerow(row)
                    file_counts[filename] = file_counts.get(filename, 0) + 1
                    total_emails += 1

                elif filename.lower().endswith(".mbox") or "phishing" in filename.lower():
                    mbox = mailbox.mbox(filepath)
                    count = 0
                    for i, msg in enumerate(mbox):
                        row = {"Source_File": f"{filename}_msg_{i+1}"}
                        for h in headers_to_extract:
                            val = msg.get(h, "")
                            if isinstance(val, bytes):
                                try:
                                    val = val.decode("utf-8", errors="ignore")
                                except:
                                    val = str(val)
                            row[h] = val
                        writer.writerow(row)
                        count += 1
                        total_emails += 1
                    file_counts[filename] = file_counts.get(filename, 0) + count

            except Exception as e:
                print(f"Error processing {filepath}: {e}")

print("Total messages processed:", total_emails)
print("CSV saved to:", csv_file_path)
