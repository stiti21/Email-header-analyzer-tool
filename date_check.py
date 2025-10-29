import csv

from email.utils import parsedate_to_datetime
from datetime import datetime

input_csv = "/home/kali/tool/email_headers.csv"
output_csv = "/home/kali/tool/date_check_results.csv"

with open(input_csv, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline="", encoding="utf-8") as outfile:

    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    writer.writerow(["Filename", "Date", "Status", "Error"])

    for row in reader:
        filename = row.get("Filename", "Unknown")
        date_str = row.get("Date", "").strip()

        try:
            # Parse date from header
            msg_date = parsedate_to_datetime(date_str)
            now = datetime.now()

            # Check logical validity
            if msg_date.year < 2000:
                status = "INVALID (Too old)"
            elif msg_date > now:
                status = "INVALID (Future date)"
            else:
                status = "VALID"

            writer.writerow([filename, date_str, status, ""])

        except Exception as e:
            writer.writerow([filename, date_str, "INVALID", f"Error: {str(e)}"])

print("✅ Done! Results saved to:", output_csv)
