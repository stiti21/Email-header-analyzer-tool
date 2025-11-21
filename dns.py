import csv
from datetime import datetime
import dns.resolver
import tldextract
import whois
import time
import random


input_file = "/home/stiti/test/csv/email_headers.csv"
output_file = "/home/stiti/test/csv/test.csv"

SUSPICIOUS_TLDS = {".top", ".xyz", ".zip", ".click", ".quest", ".shop", ".online", ".ink", ".center", ".group", ".io", ".club", ".site"}

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com"],
    "outlook": ["outlook.com"],
    "ebay": ["ebay.com"],
    "bradesco": ["bradesco.com.br"],
    "bank": ["centralbank.net", "chase.com", "citibank.com"],
    "tesla": ["tesla.com"],
    "shell": ["shell.de"],
    "starbucks": ["starbucks.com"],
    "unitedhealthcare": ["unitedhealthcare.com"],
    "healthcare": ["unitedhealthcare.com"],
    "otto": ["otto.de"],
    "mobile": ["mobile.de"],
    "gov": ["gov.br", "gov.uk", "gov.us"]
}

KNOWN_SAFE_DOMAINS = {
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 
    'google.com', 'microsoft.com', 'facebook.com', 'apple.com',
    'icloud.com', 'live.com', 'aol.com'
}

def get_domain_from_email(email):
    try:
        if "@" not in email:
            return None
        return email.split("@")[-1].strip().lower()
    except:
        return None

def get_domain_age(domain):
    if domain in KNOWN_SAFE_DOMAINS:
        return 2000  
    
    try:
        time.sleep(random.uniform(0.5, 1.5))
        
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -2  
        
        today = datetime.now()
        age = (today - creation_date).days
        return age if age > 0 else -2
        
    except Exception as e:
        return -2

def has_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except:
        return False

def is_suspicious_tld(domain):
    try:
        tld = "." + domain.split(".")[-1]
        return tld in SUSPICIOUS_TLDS
    except:
        return False

def detect_brand_impersonation(sender_domain):
    if not sender_domain:
        return None
    try:
        for brand, official_domains in BRANDS.items():
            for real_domain in official_domains:
                if brand in sender_domain and sender_domain != real_domain:
                    return brand
        return None
    except:
        return None

def has_suspicious_pattern(domain):
    try:
        name_parts = domain.split('.')
        if len(name_parts) < 2:
            return False
            
        name = name_parts[0]
        
        if len(name) > 8 and sum(c.isdigit() for c in name) > 2:
            return True  
        
        if len(name) > 12 and name.isalnum():
            return True  
        
        if any(char.isdigit() for char in name) and any(char.isalpha() for char in name):
            digit_count = sum(c.isdigit() for c in name)
            if digit_count > 3:  # Too many digits in domain name
                return True
        
        if len(name) <= 6 and name.isalnum() and not name.isalpha():
            return True
            
        return False
    except:
        return False

def extract_email_from_sender_field(sender_field):
    try:
        if "<" in sender_field and ">" in sender_field:
            start = sender_field.find("<") + 1
            end = sender_field.find(">")
            email_part = sender_field[start:end]
            if "@" in email_part:
                for part in email_part.split():
                    if "@" in part:
                        return part.strip()
        # If no <>, look for @ symbol
        elif "@" in sender_field:
            for part in sender_field.split():
                if "@" in part:
                    return part.strip()
        return sender_field.strip()
    except:
        return sender_field.strip()

def calculate_phishing_score(email):
    score = 0
    domain = get_domain_from_email(email)

    if not domain:
        return {
            "email": email,
            "domain": "",
            "age_days": -1,
            "brand_impersonation": None,
            "risk_score": 60,
            "risk_level": "High"
        }

    brand = detect_brand_impersonation(domain)
    if brand:
        score += 40

    if is_suspicious_tld(domain):
        score += 20

    if not has_mx_records(domain):
        score += 25

    if has_suspicious_pattern(domain):
        score += 30

    age = get_domain_age(domain)
    
    if age > 0:
        if age < 7:
            score += 50
        elif age < 30:
            score += 30
        elif age < 90:
            score += 15
    else:
        if domain not in KNOWN_SAFE_DOMAINS:
            score += 10  
    return {
        "email": email,
        "domain": domain,
        "age_days": age,
        "brand_impersonation": brand,
        "risk_score": score,
        "risk_level": "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    }


try:
    with open(input_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        
        emails = []
        for row in reader:
            if 'From' in row and row['From'].strip():
                sender_field = row['From'].strip()
                email = extract_email_from_sender_field(sender_field)
                if email and "@" in email:  
                    emails.append(email)
        
        print(f"Found {len(emails)} email addresses to process")

    results = []
    successful_whois = 0
    failed_whois = 0
    
    for i, email in enumerate(emails, 1):
        print(f"Processing {i}/{len(emails)}: {email}")
        result = calculate_phishing_score(email)
        results.append(result)
        
        if result['age_days'] > 0:
            successful_whois += 1
        elif result['age_days'] == -2:
            failed_whois += 1
        
        if i % 10 == 0 or i == len(emails):
            print(f"Processed {i}/{len(emails)} emails")
            print(f"WHOIS success rate: {successful_whois}/{i} ({successful_whois/i*100:.1f}%)")

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["email", "domain", "age_days", "brand_impersonation", "risk_score", "risk_level"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"All {len(emails)} emails processed. Results saved to {output_file}")

    high_risk = len([r for r in results if r['risk_level'] == 'High'])
    medium_risk = len([r for r in results if r['risk_level'] == 'Medium'])
    low_risk = len([r for r in results if r['risk_level'] == 'Low'])
    
    print(f"\n=== FINAL SUMMARY ===")
    print(f"WHOIS Statistics:")
    print(f"  Successful lookups: {successful_whois}")
    print(f"  Failed lookups: {failed_whois}")
    print(f"  Known safe domains: {len([r for r in results if r['age_days'] == 2000])}")
    
    print(f"\nRisk Summary:")
    print(f"  High risk: {high_risk} emails")
    print(f"  Medium risk: {medium_risk} emails") 
    print(f"  Low risk: {low_risk} emails")
    
    print(f"\nHigh Risk Examples:")
    high_risk_examples = [r for r in results if r['risk_level'] == 'High'][:5]
    for example in high_risk_examples:
        reason = []
        if example['brand_impersonation']:
            reason.append(f"fake {example['brand_impersonation']}")
        if example['risk_score'] >= 30:
            reason.append("suspicious pattern")
        if example['risk_score'] >= 25:
            reason.append("no MX records")
        print(f"  - {example['email']} (Score: {example['risk_score']}, Reasons: {', '.join(reason)})")

except FileNotFoundError:
    print(f"Error: {input_file} not found! Make sure it exists.")
except Exception as e:
    print(f"Error: {str(e)}")
    import traceback
    traceback.print_exc()
