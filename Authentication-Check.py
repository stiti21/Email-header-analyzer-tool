import csv

input_csv = "/home/stiti/tool/csv/email_headers.csv"
output_csv = "/home/stiti/tool/csv/auth_results.csv"

with open(input_csv, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    writer.writerow(["File", "From", "SPF", "DKIM", "Status", "Auth_Header"])

    for row in reader:
        file_name = row.get("Filename", "Unknown").strip()
        from_header = row.get("From", "Unknown").strip()
        auth = row.get("Authentication-Results", "").lower()

        if not auth or auth.strip() == "":
            spf = "MISSING"
            dkim = "MISSING"
        else:
            if any(x in auth for x in ["spf=fail", "spf=hardfail"]):
                spf = "FAIL"
            elif "spf=pass" in auth:
                spf = "PASS"
            elif any(x in auth for x in ["spf=softfail", "spf=neutral"]):
                spf = "SOFTFAIL"
            else:
                spf = "NONE"  
            if "dkim=fail" in auth:
                dkim = "FAIL"
            elif "dkim=pass" in auth:
                dkim = "PASS"
            elif "dkim=neutral" in auth:
                dkim = "NEUTRAL"
            else:
                dkim = "NONE" 

        if spf == "FAIL" or dkim == "FAIL":
            status = "PHISHING"
        elif spf == "MISSING" or dkim == "MISSING":
            status = "SUSPICIOUS"  
        elif spf == "SOFTFAIL" or dkim == "NEUTRAL":
            status = "RISKY"
        elif spf == "NONE" or dkim == "NONE":
            status = "SUSPICIOUS"  
        else:
            status = "SAFE"

        writer.writerow([file_name, from_header, spf, dkim, status, auth])

print("Done! Results saved to:", output_csv)
