
import csv

input_csv = "/home/kali/tool/email_headers.csv"
output_csv = "/home/kali/tool/csv/from_return_check.csv"

match_count = 0
differ_count = 0

with open(input_csv, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=["Filename", "From", "To", "CC", "Return-Path", "Message-ID", "Status"])
    writer.writeheader()

    for row in reader:
        filename = row.get("Filename", "")
        from_addr = row.get("From", "")
        to_addr = row.get("To", "")
        cc_addr = row.get("Cc", "")
        return_addr = row.get("Return-Path", "")
        msg_id = row.get("Message-ID", "")

        status = "MATCH" if from_addr == return_addr else "DIFFER"

        if status == "MATCH":
            match_count += 1
        else:
            differ_count += 1

        writer.writerow({
            "Filename": filename,
            "From": from_addr,
            "To": to_addr,
            "CC": cc_addr,
            "Return-Path": return_addr,
            "Message-ID": msg_id,
            "Status": status
        })

print("Results saved to:", output_csv)
print(f"MATCH emails: {match_count}")
print(f"DIFFER emails: {differ_count}")
print(f"Total emails analyzed: {match_count + differ_count}")
