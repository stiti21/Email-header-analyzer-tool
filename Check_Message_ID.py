import email
from email import policy
import csv
import re

emails_file = ""
output_csv = "suspicious_emails.csv"

def check_message_id(mid):
    if not mid or "@" not in mid or len(mid)<5 or len(mid)>200: 
        return "Message-ID problem"
    if re.search(r"\s", mid):
        return "Spaces in Message-ID"
    if re.search(r"[^a-zA-Z0-9@._<>-]", mid):
        return "Strange chars in Message-ID"
    return ""

with open(emails_file,"r",encoding="utf-8",errors="ignore") as f:
    emails = f.read().split("\nFrom ")

with open(output_csv,"w",newline="",encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile,fieldnames=["Email_Number","From","To","Return-Path","CC","Message-ID","Issues"])
    writer.writeheader()
    for i, raw in enumerate(emails, start=1):
        try:
            msg = email.message_from_string(raw,policy=policy.default)
        except:
            continue
        issues=[]
        mid_issue = check_message_id(msg.get("Message-ID",""))
        if mid_issue: 
            issues.append(mid_issue)
        if issues:
            writer.writerow({
                "Email_Number": i,
                "From": msg.get("From",""),
                "To": msg.get("To",""),
                "Return-Path": msg.get("Return-Path",""),
                "CC": msg.get("Cc",""),
                "Message-ID": msg.get("Message-ID",""),
                "Issues": "; ".join(issues)
            })

print("Done! Suspicious emails saved to:", output_csv)
