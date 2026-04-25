import email
from email import policy
from email.utils import parseaddr
from bs4 import BeautifulSoup
import urllib.parse
from collections import Counter
import re

def extract_features_from_parts(sender: str, subject: str, body_text: str, html_content: str = "") -> dict:
    """
    Core feature extraction logic used by both inference and training.
    """
    _, sender_email = parseaddr(sender)
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    
    features = {}
    features["subject_len"] = len(str(subject))
    features["has_sender"] = 1 if sender_email else 0
    features["num_attachments"] = 0 # Not easily captured from parts alone
    
    # Simple base domain extractor (e.g. sales.google.com -> google.com)
    def get_base_domain(domain_str):
        if not domain_str: return ""
        parts = domain_str.split('.')
        if len(parts) >= 2:
            return ".".join(parts[-2:]).lower()
        return domain_str.lower()

    sender_base_domain = get_base_domain(sender_domain)
    
    total_hyperlinks = 0
    ext_hyperlinks = 0
    null_self_hyperlinks = 0
    domains = []
    
    # If no HTML but we have body text, look for URLs in text
    if not html_content and body_text:
        # Simple regex for URLs in plain text
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body_text)
        total_hyperlinks = len(urls)
        for url in urls:
            try:
                if not url.startswith('http'): url = 'http://' + url
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc.lower()
                if domain:
                    domains.append(domain)
                    link_base_domain = get_base_domain(domain)
                    if not sender_base_domain or link_base_domain != sender_base_domain:
                        ext_hyperlinks += 1
            except:
                pass
    elif html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        links = soup.find_all("a", href=True)
        total_hyperlinks = len(links)
        
        for a in links:
            href = a['href'].strip()
            if not href or href == "#" or href.startswith("javascript:"):
                null_self_hyperlinks += 1
                continue
            try:
                parsed_url = urllib.parse.urlparse(href)
                domain = parsed_url.netloc.lower()
                if domain:
                    domains.append(domain)
                    link_base_domain = get_base_domain(domain)
                    if not sender_base_domain or link_base_domain != sender_base_domain:
                        ext_hyperlinks += 1
            except:
                null_self_hyperlinks += 1
                
    features["PctExtHyperlinks"] = float(ext_hyperlinks / total_hyperlinks) if total_hyperlinks > 0 else 0.0
    ext_null_self = ext_hyperlinks + null_self_hyperlinks
    features["PctExtNullSelfRedirectHyperlinksRT"] = float(ext_null_self / total_hyperlinks) if total_hyperlinks > 0 else 0.0
    
    FrequentDomainNameMismatch = 0
    if domains:
        from collections import Counter
        most_frequent_domain = Counter(domains).most_common(1)[0][0]
        most_frequent_base = get_base_domain(most_frequent_domain)
        if sender_base_domain and most_frequent_base != sender_base_domain:
            FrequentDomainNameMismatch = 1
    elif total_hyperlinks > 0 and ext_hyperlinks == total_hyperlinks:
        FrequentDomainNameMismatch = 1
        
    features["FrequentDomainNameMismatch"] = float(FrequentDomainNameMismatch)
    features["total_links"] = float(total_hyperlinks)
    features["body_text"] = body_text
    features["sender_email"] = sender_email
    features["extracted_domains"] = domains # Added for Threat Intel
    
    return features

def extract_features_from_eml(eml_bytes: bytes) -> dict:
    """
    Parses a raw .eml byte sequence and extracts features for the ML pipeline.
    """
    msg = email.message_from_bytes(eml_bytes, policy=policy.default)
    
    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    
    text_content = []
    html_content = ""
    num_attachments = 0
    
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get("Content-Disposition", "").startswith("attachment"):
            num_attachments += 1
            
        content_type = part.get_content_type()
        try:
            payload = part.get_content()
            if content_type == "text/plain":
                text_content.append(payload)
            elif content_type == "text/html":
                html_content += payload
        except Exception:
            pass
            
    full_text = "\n".join(text_content).strip()
    if not full_text and html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        full_text = soup.get_text(separator=' ', strip=True)
        
    features = extract_features_from_parts(sender, subject, full_text, html_content)
    features["num_attachments"] = num_attachments
    return features

