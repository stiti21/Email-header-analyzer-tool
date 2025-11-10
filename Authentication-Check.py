import csv

input_csv = "/home/stiti/test/csv/email_headers.csv"
output_csv = "/home/stiti/test/csv/auth_results.csv"

total_emails = 0
safe_count = 0
phishing_count = 0

with open(input_csv, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    writer.writerow(["Filename", "From", "SPF_Status", "DKIM_Status", "Result"])

    for row in reader:
        total_emails += 1
        filename = row.get("Filename", "")
        from_header = row.get("From", "Unknown").strip()
        auth = row.get("Authentication-Results", "").lower()

        if not auth:
            spf = "MISSING"
            dkim = "MISSING"
        else:
            if any(x in auth for x in ["spf=fail", "spf=hardfail"]):
                spf = "FAIL"
            elif "spf=pass" in auth:
                spf = "PASS"
            else:
                spf = "NONE"

            if "dkim=fail" in auth:
                dkim = "FAIL"
            elif "dkim=pass" in auth:
                dkim = "PASS"
            else:
                dkim = "NONE"

        if spf == "PASS" and dkim == "PASS":
            result = "NORMAL"
            safe_count += 1
        else:
            result = "PHISHING"
            phishing_count += 1

        writer.writerow([filename, from_header, spf, dkim, result])

print("Done! Results saved to:", output_csv)
print(f"Total emails processed: {total_emails}")
print(f"Normal emails: {safe_count}")
print(f"Phishing emails: {phishing_count}")
