import email
import csv
import os
import re
import mailbox
from email.utils import parsedate_to_datetime
from email.header import decode_header  

class EmailHeaderExtractor:
    def __init__(self):
        self.headers_to_extract = [
            'From', 'To', 'Subject', 'Date', 'Message-ID',
            'Return-Path', 'Received', 'Reply-To', 'Sender',
            'Content-Type', 'Authentication-Results',
            'DKIM-Signature', 'X-Originating-IP'
        ]
        
    def decode_header_value(self, header_value):
        try:
            if isinstance(header_value, str):
                return header_value.strip()
            else:
                decoded_parts = []
                if hasattr(header_value, '__iter__') and not isinstance(header_value, str):
                    for part in header_value:
                        if isinstance(part, tuple):
                            # Decode encoded parts (like =?utf-8?B?...?=)
                            bytes_data, encoding = part
                            if encoding:
                                decoded_parts.append(bytes_data.decode(encoding, errors='ignore'))
                            else:
                                decoded_parts.append(bytes_data.decode('utf-8', errors='ignore'))
                        else:
                            decoded_parts.append(str(part))
                    return ' '.join(decoded_parts).strip()
                else:
                    return str(header_value).strip()
        except:
            return str(header_value).strip()
        
    def extract_headers_and_body(self, msg):
        try:
            data = {}
            
            for header in self.headers_to_extract:
                header_value = msg.get(header, '')
                data[header] = self.decode_header_value(header_value)
            
            data['Body_Text'] = self.extract_body_text(msg)
            data['Body_HTML'] = self.extract_body_html(msg)
            
            return data
            
        except Exception as e:
            print(f"Error processing email: {str(e)}")
            return {header: '' for header in self.headers_to_extract}
    
    def extract_from_eml_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                email_content = file.read()
            
            msg = email.message_from_string(email_content)
            data = self.extract_headers_and_body(msg)
            data['Filename'] = os.path.basename(file_path)
            return data
            
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")
            empty_data = {header: '' for header in self.headers_to_extract}
            empty_data['Filename'] = os.path.basename(file_path)
            empty_data['Body_Text'] = ''
            empty_data['Body_HTML'] = ''
            return empty_data
    
    def extract_from_mbox_file(self, file_path):
        """Extract from .mbox file (multiple emails)"""
        all_emails = []
        try:
            mbox = mailbox.mbox(file_path)
            print(f"Processing mbox file: {file_path} ({len(mbox)} emails)")
            
            for i, msg in enumerate(mbox):
                try:
                    data = self.extract_headers_and_body(msg)
                    data['Filename'] = f"{os.path.basename(file_path)}_email_{i+1}"
                    all_emails.append(data)
                except Exception as e:
                    print(f"  Error with email {i+1} in mbox: {str(e)}")
                    empty_data = {header: '' for header in self.headers_to_extract}
                    empty_data['Filename'] = f"{os.path.basename(file_path)}_email_{i+1}_error"
                    empty_data['Body_Text'] = ''
                    empty_data['Body_HTML'] = ''
                    all_emails.append(empty_data)
                
                if (i + 1) % 100 == 0:
                    print(f"  Processed {i + 1} emails from mbox...")
            
            return all_emails
            
        except Exception as e:
            print(f"Error processing mbox {file_path}: {str(e)}")
            empty_data = {header: '' for header in self.headers_to_extract}
            empty_data['Filename'] = os.path.basename(file_path) + "_error"
            empty_data['Body_Text'] = ''
            empty_data['Body_HTML'] = ''
            return [empty_data]
    
    def extract_body_text(self, msg):
        try:
            body_text = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode('utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
            
            return body_text.strip()
        except:
            return ""
    
    def extract_body_html(self, msg):
        try:
            body_html = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html += payload.decode('utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_html = payload.decode('utf-8', errors='ignore')
            
            return body_html.strip()
        except:
            return ""
    
    def process_directory(self, input_directory, output_csv):
        all_data = []
        
        email_extensions = {'.eml', '.mbox'}
        
        print("?? Starting Email Header and Body Extraction...")
        print("Supported formats: .eml (single emails) and .mbox (email collections)")
        
        for filename in os.listdir(input_directory):
            file_path = os.path.join(input_directory, filename)
            if os.path.isfile(file_path):
                file_ext = os.path.splitext(filename.lower())[1]
                
                if file_ext == '.eml':
                    print(f"Processing .eml file: {filename}")
                    email_data = self.extract_from_eml_file(file_path)
                    all_data.append(email_data)
                    
                elif file_ext == '.mbox':
                    print(f"Processing .mbox file: {filename}")
                    mbox_emails = self.extract_from_mbox_file(file_path)
                    all_data.extend(mbox_emails)
        
        if all_data:
            with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Filename'] + self.headers_to_extract + ['Body_Text', 'Body_HTML']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for data in all_data:
                    writer.writerow(data)
            
            print(f"? Extraction completed! {len(all_data)} emails processed.")
            print(f"?? Results saved to: {output_csv}")
            
            successful = len([d for d in all_data if any(d[header] for header in self.headers_to_extract)])
            print(f"?? Success rate: {successful}/{len(all_data)} emails successfully extracted")
            
        else:
            print("? No .eml or .mbox files found!")

if __name__ == "__main__":
    extractor = EmailHeaderExtractor()
    input_dir = "/home/stiti/data" 
    output_file = "/home/stiti/csv/email.csv"
    extractor.process_directory(input_dir, output_file)
