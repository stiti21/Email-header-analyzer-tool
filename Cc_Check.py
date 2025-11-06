import csv

input_file = '/home/kali/tool/email_headers.csv'
output_file = '/home/kali/tool/cc_check_results.csv'

output_data = [['Filename', 'Cc', 'Cc_Status', 'Same_Domain', 'Final_Status', 'Error']]

with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
    reader = csv.DictReader(infile)
    for row in reader:
        try:
            filename = row.get('Filename', '').strip()
            cc_field = row.get('Cc', '')
            cc_list = [x.strip() for x in cc_field.split(',') if x.strip()]

            if len(cc_list) > 10:
                cc_status = "FAIL"
            elif len(cc_list) > 0:
                cc_status = "NEUTRAL"
            else:
                cc_status = "PASS"

            domains = [email.split('@')[-1] for email in cc_list if '@' in email]
            same_domain = "Yes" if len(set(domains)) <= 1 and domains else "No"

            # الحالة النهائية
            if cc_status == "FAIL" or same_domain == "No":
                final_status = "Phishing"
            elif cc_status == "NEUTRAL":
                final_status = "Neutral"
            else:
                final_status = "Safe"

            output_data.append([filename, cc_field, cc_status, same_domain, final_status, ''])
        except Exception as e:
            output_data.append([row.get('Filename',''), cc_field, 'Unknown', 'Unknown', 'Unknown', f'Error: {str(e)}'])

with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("✅ Done! Results saved to:", output_file)

