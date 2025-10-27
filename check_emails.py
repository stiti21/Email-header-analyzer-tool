import os
import email
from email import policy
import csv

folder = "/home/stiti/tool/dataset/emails"
output_csv = "/home/stiti/tool/csv/from_return_check.csv"

with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = ["Filename", "From", "To", "CC", "Return-Path", "Message-ID", "Status"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.startswith("."):
                continue
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                msg = email.message_from_file(f, policy=policy.default)
                
                from_addr = msg.get("From", "")
                to_addr = msg.get("To", "")
                cc_addr = msg.get("Cc", "")
                return_addr = msg.get("Return-Path", "")
                msg_id = msg.get("Message-ID", "")

                status = "MATCH" if from_addr == return_addr else "DIFFER"

                writer.writerow({
                    "Filename": file,
                    "From": from_addr,
                    "To": to_addr,
                    "CC": cc_addr,
                    "Return-Path": return_addr,
                    "Message-ID": msg_id,
                    "Status": status
                })

print("Results saved to:", output_csv)


