import csv

input_file = "/home/kali/tool/email_headers.csv"
output_file = "/home/kali/tool/csv/phishing_check_results.csv"

output_data = [["Filename", "From", "Return-Path", "Message-ID", "Phishing", "Reason"]]

total = 0
phishing_count = 0
safe_count = 0

def simple_check(from_header, return_path, msg_id):
    if not from_header or not return_path or not msg_id:
        return "Unknown", "Missing required headers"
    
    from_domain = from_header.split("@")[-1].replace(">", "").replace("<", "") if "@" in from_header else ""
    return_domain = return_path.split("@")[-1].replace(">", "").replace("<", "") if "@" in return_path else ""
    msg_domain = msg_id.split("@")[-1].replace(">", "").replace("<", "") if "@" in msg_id else ""

    if from_domain != return_domain:
        return "Phishing", "From and Return-Path domains differ"
    elif msg_domain != from_domain:
        return "Phishing", "Message-ID domain differs from sender"
    else:
        return "Safe", "Domains match"

with open(input_file, "r", encoding="utf-8", errors="ignore") as infile:
    reader = csv.DictReader(infile)
    for row in reader:
        total += 1
        filename = row.get("Filename", "")
        from_header = row.get("From", "")
        return_path = row.get("Return-Path", "")
        msg_id = row.get("Message-ID", "")
        
        result, reason = simple_check(from_header, return_path, msg_id)

        if "Phishing" in result:
            phishing_count += 1
        elif "Safe" in result:
            safe_count += 1

        output_data.append([filename, from_header, return_path, msg_id, result, reason])

with open(output_file, "w", newline="", encoding="utf-8") as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("Done! Results saved to phishing_check_results.csv")
print(f"Total emails: {total}")
print(f"Phishing detected: {phishing_count}")
print(f"Safe emails: {safe_count}")
