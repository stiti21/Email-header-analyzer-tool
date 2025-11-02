import csv

input_file = '/home/kali/tool/email_headers.csv'
output_file = '/home/kali/tool/cc_check_results.csv'

output_data = [['Filename', 'Cc', 'Cc_Status', 'Final_Status', 'Error']]

with open(inputimport_file, 'r', encoding='utf-8', errors='replace') as infile:
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
            final_status = "Phishing" if cc_status == "FAIL" else ("Neutral" if cc_status == "NEUTRAL" else "Safe")
            output_data.append([filename, cc_field, cc_status, final_status, ''])
        except Exception as e:
            output_data.append([row.get('Filename',''), cc_field, 'Unknown', 'Unknown', f'Error: {str(e)}'])

with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("Done! Results saved to:", output_file)
