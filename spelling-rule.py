import os
import email
from email import policy
import csv
import re
from spellchecker import SpellChecker

EMAIL_FOLDER = "/home/stiti/tool/dataset/emails"
OUTPUT_FILE = "/home/stiti/tool/csv/spell_check_results.csv"

spell = SpellChecker()

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    text = part.get_payload(decode=True).decode(errors="ignore")
                    body += text
                except:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
        except:
            body = ""
    return body

def spelling_rule(text):
    clean_text = re.sub(r'[^a-zA-Z\s]', ' ', text)
    words = [w.lower() for w in clean_text.split() if len(w) > 3]
    misspelled = spell.unknown(words)

    if misspelled:
        short_list = list(misspelled)[:10]
        return "Suspicious", f"Spelling mistakes: {', '.join(short_list)}"
    else:
        return "Safe", "No spelling mistakes"

results = []

for filename in os.listdir(EMAIL_FOLDER):
    filepath = os.path.join(EMAIL_FOLDER, filename)
    try:
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except Exception:
        continue

    body = extract_body(msg)
    status, details = spelling_rule(body)

    preview = body[:100].replace("\n", " ") 
    results.append([filename, preview, status, details])

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Filename", "Body_Preview", "Status", "Details"])
    writer.writerows(results)

print(" Spell check completed.")
print("Results saved to:", OUTPUT_FILE)
print("Total emails processed:", len(results))
