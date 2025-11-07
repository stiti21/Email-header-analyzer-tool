import csv

input_csv = "/home/kali/tool/email_headers.csv"
output_csv = "/home/kali/tool/csv/auth_results.csv"

phishing_count = 0
safe_count = 0

with open(input_csv, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    writer.writerow(["From", "SPF", "DKIM", "Status", "Auth_Header"])

    for row in reader:
        from_header = row.get("From", "Unknown").strip()
        auth = row.get("Authentication-Results", "").lower()

        if not auth:
            spf = dkim = "MISSING"
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

        # Determine email status: any non-PASS is PHISHING
        if spf == "PASS" and dkim == "PASS":
            status = "SAFE"
            safe_count += 1
        else:
            status = "PHISHING"
            phishing_count += 1

        writer.writerow([from_header, spf, dkim, status, auth])

print("Done! Results saved to:", output_csv)
print(f"Phishing emails: {phishing_count}")
print(f"Safe emails: {safe_count}")

