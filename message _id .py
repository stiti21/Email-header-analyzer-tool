import csv

input_file = '/home/stiti/test/csv/email_headers.csv'
output_file = '/home/stiti/test/csv/missing_message_ids.csv'

with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=['Filename', 'Message-ID', 'Missing_Message_ID'])
    writer.writeheader()
    
    missing_count = 0
    total_count = 0
    
    for row in reader:
        total_count += 1
        message_id = row.get('Message-ID', '')
        is_missing = not message_id or message_id.strip() == ''
        
        if is_missing:
            missing_count += 1
        
        writer.writerow({
            'Filename': row.get('Filename', ''),
            'Message-ID': message_id,
            'Missing_Message_ID': is_missing
        })

print(f"Analysis complete! Saved to: {output_file}")
print(f"Total emails: {total_count}")
print(f"Missing Message-IDs: {missing_count}")
