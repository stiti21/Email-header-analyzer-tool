import os             
import email          
from email import policy   
import csv             

directory_path = "/home/stiti/tool/dataset/emails"  

headers_to_extract = ["From", "To", "Cc", "Date", "Message-ID", "Return-Path" ,"Authentication-Results"]

csv_file_path = "/home/stiti/tool/csv/email_headers.csv"  
with open(csv_file_path, mode="w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["Filename"] + headers_to_extract)
    
    writer.writeheader()

    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            if filename.startswith("."):
                continue

            filepath = os.path.join(root, filename)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as eml_file:
                    msg = email.message_from_file(eml_file, policy=policy.default)

             
                row = {"Filename": filename}  
                for header in headers_to_extract:
                    row[header] = msg.get(header, "")

           
                writer.writerow(row)

            except Exception as e:
                print(f"Error reading {filepath}: {e}")
