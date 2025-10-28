import csv


with open('/home/stiti/tool/csv/email_headers.csv', 'r') as infile:
    reader = csv.DictReader(infile)

   
    output_data = [['Filename', 'Message-ID', 'Phishing']]

    for row in reader:
        
        msg_id_domain = row['Message-ID'].split('@')[-1].strip('>')
        return_path_domain = row['Return-Path'].split('@')[-1].strip('>')

        )
        is_phishing = msg_id_domain != return_path_domain

        output_data.append([row['Filename'], row['Message-ID'], is_phishing])


with open('/home/stiti/tool/csv/phishing_check_results.csv', 'w', newline='') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("Done! Check phishing_check_results.csv")
