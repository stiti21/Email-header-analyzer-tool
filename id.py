import csv

input_file = '/home/stiti/tool/csv/email_headers.csv'
output_file = '/home/stiti/tool/csv/phishing_check_results.csv'

output_data = [['Filename', 'Message-ID', 'Phishing', 'Error']]

with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
    reader = csv.DictReader(infile)

    for row in reader:
        try:
            msg_id = row.get('Message-ID', '').strip()
            return_path = row.get('Return-Path', '').strip()

            if not msg_id or not return_path:
                raise ValueError("Missing Message-ID or Return-Path")

            msg_id_domain = msg_id.split('@')[-1].strip('>')
            return_path_domain = return_path.split('@')[-1].strip('>')

            is_phishing = msg_id_domain != return_path_domain

            output_data.append([row.get('Filename',''), msg_id, is_phishing, ''])

        except Exception as e:
            output_data.append([row.get('Filename',''), row.get('Message-ID',''), 'Unknown', f'Error: {str(e)}'])

with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("Done! Check phishing_check_results.csv")
