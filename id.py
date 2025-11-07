import os
import email
from email import policy
import csv
import mailbox

directory_path = "/home/stiti/tool/dataset/emails"
output_file = '/home/stiti/tool/csv/phishing_check_results.csv'

headers_to_extract = ["From", "To", "Cc", "Date", "Message-ID", "Return-Path", "Authentication-Results"]


output_data = [['Filename', 'Message-ID', 'Return-Path', 'From', 'To', 'Phishing', 'Error']]

def check_phishing(msg_id, return_path):
    
    try:
        if not msg_id or not return_path:
            raise ValueError("Missing Message-ID or Return-Path")

        msg_id_domain = msg_id.split('@')[-1].strip('>')
        return_path_domain = return_path.split('@')[-1].strip('>')

        return msg_id_domain != return_path_domain, ''
    except Exception as e:
        return 'Unknown', f'Error: {str(e)}'

for root, dirs, files in os.walk(directory_path):
    for filename in files:
        if filename.startswith("."):
            continue

        filepath = os.path.join(root, filename)

        try:
            if filename.endswith('.eml'):
                with open(filepath, "r", encoding="utf-8", errors="ignore") as eml_file:
                    msg = email.message_from_file(eml_file, policy=policy.default)

                msg_id = msg.get("Message-ID", "").strip()
                return_path = msg.get("Return-Path", "").strip()
                from_header = msg.get("From", "").strip()
                to_header = msg.get("To", "").strip()

                is_phishing, error = check_phishing(msg_id, return_path)
                
                output_data.append([
                    filename, 
                    msg_id, 
                    return_path, 
                    from_header, 
                    to_header, 
                    is_phishing, 
                    error
                ])
            
            elif filename == 'phishing3.mbox':
                mbox = mailbox.mbox(filepath)
                for i, msg in enumerate(mbox):
                    msg_id = msg.get("Message-ID", "").strip()
                    return_path = msg.get("Return-Path", "").strip()
                    from_header = msg.get("From", "").strip()
                    to_header = msg.get("To", "").strip()

                    is_phishing, error = check_phishing(msg_id, return_path)
                    
                    output_data.append([
                        f"phishing3_msg_{i+1}", 
                        msg_id, 
                        return_path, 
                        from_header, 
                        to_header, 
                        is_phishing, 
                        error
                    ])

        except Exception as e:
            output_data.append([filename, '', '', '', '', 'Unknown', f'Processing Error: {str(e)}'])

with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(output_data)

print("Done! Check phishing_check_results.csv")
