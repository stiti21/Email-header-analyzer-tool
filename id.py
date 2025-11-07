import os
import csv

directory_path = "/home/stiti/tool/csv/email_headers.csv"
output_file = '/home/stiti/tool/csv/phishing_check_results.csv'

output_data = [['Filename', 'Message-ID', 'Return-Path', 'From', 'To', 'Phishing', 'Error']]

def check_phishing(msg_id, return_path, from_header):
    try:
        if not msg_id or not return_path or not from_header:
            return 'Unknown', 'Missing required headers'

        msg_id_domain = msg_id.split('@')[-1].strip('>')
        return_path_domain = return_path.split('@')[-1].strip('>')
        
        from_email = from_header
        if '<' in from_header and '>' in from_header:
            from_email = from_header.split('<')[-1].split('>')[0]
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''

        return_path_matches_from = return_path_domain == from_domain
        
        msg_id_suspicious = msg_id_domain != from_domain
        
        common_legitimate_domains = ['hotmail.com', 'gmail.com', 'yahoo.com', 'university.edu', 
                                   'services.org', 'acme-corp.com', 'banking.com']
        
        return_path_suspicious = (return_path_domain != from_domain and 
                                from_domain in common_legitimate_domains and
                                return_path_domain not in common_legitimate_domains)

        is_phishing = (not return_path_matches_from) and (msg_id_suspicious or return_path_suspicious)
        
        return is_phishing, ''

    except Exception as e:
        return 'Unknown', f'Error: {str(e)}'

try:
    with open(directory_path, 'r', encoding='utf-8', errors='ignore') as csvfile:
        reader = csv.reader(csvfile)
        
        for row in reader:
            if len(row) < 6:  
                continue
                
            filename = row[0].strip()
            from_header = row[1].strip()
            to_header = row[2].strip()
            msg_id = row[4].strip() if len(row) > 4 else ''
            return_path = row[5].strip() if len(row) > 5 else ''
            
            if not filename or filename == 'Filename':
                continue
            
            is_phishing, error = check_phishing(msg_id, return_path, from_header)
            
            output_data.append([
                filename, 
                msg_id, 
                return_path, 
                from_header, 
                to_header, 
                is_phishing, 
                error
            ])

except Exception as e:
    output_data.append(['', '', '', '', '', 'Unknown', f'CSV Processing Error: {str(e)}'])

with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("Done! Check phishing_check_results.csv")
