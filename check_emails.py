import os
import email
from email import policy

folder = "/home/stiti/tool/dataset/emails"

for root, dirs, files in os.walk(folder):
    for file in files:
        if file.startswith("."):
            continue
        path = os.path.join(root, file)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            msg = email.message_from_file(f, policy=policy.default)
            
            from_addr = msg.get("From", "")
            return_addr = msg.get("Return-Path", "")
            
            # simplest output
            if from_addr != return_addr:
                print(file, "DIFFER")
            else:
                print(file, "MATCH")
