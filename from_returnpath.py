import csv
import re

input_csv = "/home/stiti/test/csv/email_headers.csv"
output_csv = "/home/stiti/test/csv/from_return_check.csv"

def get_email(text):
    """Get only the email address from text"""
    email = re.findall(r'[\w\.-]+@[\w\.-]+', str(text))
    return email[0].lower() if email else ""

match = differ = 0

with open(input_csv, "r") as infile, open(output_csv, "w", newline="") as outfile:
    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=["Filename", "From_Email", "Return_Email", "Status"])
    writer.writeheader()

    for row in reader:
        from_email = get_email(row["From"])
        return_email = get_email(row["Return-Path"])
        
        status = "MATCH" if from_email == return_email else "DIFFER"
        
        if status == "MATCH":
            match += 1
        else:
            differ += 1
            
        writer.writerow({
            "Filename": row["Filename"],
            "From_Email": from_email, 
            "Return_Email": return_email,
            "Status": status
        })

print(f"Results saved to: {output_csv}")
print(f"MATCH: {match}, DIFFER: {differ}, Total: {match + differ}")
