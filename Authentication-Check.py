import csv

input_csv = "/home/kali/tool/email_headers.csv"
output_csv = "/home/kali/tool/auth_results.csv"

with open(input_csv, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    writer.writerow(["File", "SPF", "DKIM","Status"])

    for row in reader:
        file_name = row.get("File", "Unknown").strip()
        auth = row.get("Authentication-Results", "").lower()

        spf = "FAIL" if "spf=fail" in auth else "PASS"  # SPF check
        dkim = "FAIL" if "dkim=fail" in auth else "PASS"  # DKIM check
        status="Phishing" if spf == "FAIL" or  dkim == "FAIL" else "Safe"


        writer.writerow([file_name, spf, dkim, status])

print("✅ Done! Results saved to:", output_csv)

