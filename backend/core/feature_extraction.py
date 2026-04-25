import email
from email import policy
from email.utils import parseaddr
from bs4 import BeautifulSoup
import urllib.parse
from collections import Counter
import re

def extract_features_from_eml(eml_bytes: bytes) -> dict:
    """
    Parses a raw .eml byte sequence and extracts features for the ML pipeline.
    """
    msg = email.message_from_bytes(eml_bytes, policy=policy.default)
    
    features = {}
    
    # 1. Parse Headers
    sender = msg.get("From", "")
    _, sender_email = parseaddr(sender)
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    
    features["subject_len"] = len(str(msg.get("Subject", "")))
    features["has_sender"] = 1 if sender_email else 0
    features["num_attachments"] = 0
    
    text_content = []
    html_content = ""
    
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        
        if part.get("Content-Disposition", "").startswith("attachment"):
            features["num_attachments"] += 1
            
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
    
    # Simple fallback: if no plain text, extract text from HTML
    if not full_text and html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        full_text = soup.get_text(separator=' ', strip=True)
        
    features["body_text"] = full_text
    
    # 2. Extract Hyperlinks from HTML
    total_hyperlinks = 0
    ext_hyperlinks = 0
    null_self_hyperlinks = 0
    domains = []
    
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        links = soup.find_all("a", href=True)
        total_hyperlinks = len(links)
        
        for a in links:
            href = a['href'].strip()
            
            # Check for null or empty
            if not href or href == "#" or href.startswith("javascript:"):
                null_self_hyperlinks += 1
                continue
                
            try:
                parsed_url = urllib.parse.urlparse(href)
                domain = parsed_url.netloc.lower()
                
                if domain:
                    domains.append(domain)
                    if not sender_domain or domain != sender_domain:
                        ext_hyperlinks += 1
                else:
                    # likely a relative link, self-redirect/internal
                    pass
            except Exception:
                # invalid URL
                null_self_hyperlinks += 1
                
    # Feature Calculations
    PctExtHyperlinks = (ext_hyperlinks / total_hyperlinks) if total_hyperlinks > 0 else 0.0
    
    # For simplicity, combine external, null, self redirect
    ext_null_self = ext_hyperlinks + null_self_hyperlinks
    PctExtNullSelfRedirectHyperlinksRT = (ext_null_self / total_hyperlinks) if total_hyperlinks > 0 else 0.0
    
    FrequentDomainNameMismatch = 0
    if domains:
        most_frequent_domain = Counter(domains).most_common(1)[0][0]
        if sender_domain and most_frequent_domain != sender_domain:
            FrequentDomainNameMismatch = 1
    elif total_hyperlinks > 0 and ext_hyperlinks == total_hyperlinks:
        FrequentDomainNameMismatch = 1
        
    features["PctExtHyperlinks"] = float(PctExtHyperlinks)
    features["PctExtNullSelfRedirectHyperlinksRT"] = float(PctExtNullSelfRedirectHyperlinksRT)
    features["FrequentDomainNameMismatch"] = float(FrequentDomainNameMismatch)
    features["total_links"] = float(total_hyperlinks)
    
    return features
