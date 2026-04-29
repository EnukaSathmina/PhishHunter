# utils/constants.py

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'banking', 'paypal', 'appleid', 'icloud', 'microsoft',
    'amazon', 'security', 'alert', 'validate', 'authenticate',
    'unlock', 'suspended', 'restricted', 'billing', 'payment'
]

# Risky TLDs commonly abused by phishers
RISKY_TLDS = ['.xyz', '.top', '.click', '.online', '.club', '.site', '.win', '.bid', '.loan', '.men']

# Legitimate brand domains for typosquatting detection
POPULAR_BRANDS = [
    'google', 'facebook', 'amazon', 'paypal', 'microsoft',
    'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
    'bankofamerica', 'chase', 'wellsfargo', 'gmail', 'yahoo'
]

# Phishing detection thresholds
RISK_SCORES = {
    'CRITICAL': 80,
    'HIGH': 60,
    'MEDIUM': 40,
    'LOW': 20
}

# Time thresholds (in days)
NEW_DOMAIN_THRESHOLD = 30      # Domains < 30 days are suspicious
VERY_NEW_THRESHOLD = 7         # Domains < 7 days are highly suspicious

# SSL thresholds
SSL_SHORT_VALIDITY_THRESHOLD = 90   # Certs valid for < 90 days? Suspicious