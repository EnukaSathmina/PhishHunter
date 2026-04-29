# checks/url_analyzer.py
import re
from urllib.parse import urlparse
from utils.constants import SUSPICIOUS_KEYWORDS, RISKY_TLDS

class URLAnalyzer:
    """
    Static analysis of URL structure and patterns.
    Checks for:
    - Suspicious keywords
    - URL length anomalies
    - Excessive subdomains
    - IP address usage (instead of domain)
    - Risky TLDs
    - Multiple slashes/redirections
    """
    
    def __init__(self):
        self.results = {}
    
    def check(self, url):
        """
        Analyze URL patterns.
        Returns dict with analysis results.
        """
        result = {
            'url': url,
            'length': len(url),
            'is_too_long': False,
            'uses_ip': False,
            'suspicious_keywords_found': [],
            'subdomain_count': 0,
            'has_multiple_dashes': False,
            'has_hex_encoding': False,
            'risky_tld': False,
            'risk_contribution': 0
        }
        
        # Check URL length (phishing URLs are often extremely long)
        if result['length'] > 100:
            result['is_too_long'] = True
            result['risk_contribution'] += 5 if result['length'] > 75 else 0
        
        # Check for IP address instead of domain name
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.search(ip_pattern, url):
            result['uses_ip'] = True
            result['risk_contribution'] += 30  # IP-based URLs are very suspicious
        
        # Check for suspicious keywords
        url_lower = url.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                result['suspicious_keywords_found'].append(keyword)
                result['risk_contribution'] += 3  # Each keyword adds small risk
        result['risk_contribution'] = min(result['risk_contribution'] + len(result['suspicious_keywords_found']) * 2, 25)
        
        # Parse URL for subdomain analysis
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            subdomain_parts = netloc.split('.')
            if len(subdomain_parts) > 2:  # More than 'domain.tld'
                result['subdomain_count'] = len(subdomain_parts) - 2
                if result['subdomain_count'] >= 3:
                    result['risk_contribution'] += 15  # Excessive subdomains
                elif result['subdomain_count'] >= 2:
                    result['risk_contribution'] += 8
        except:
            pass
        
        # Check for multiple dashes (legit sites rarely have many dashes)
        dash_count = url.count('-')
        if dash_count > 3:
            result['has_multiple_dashes'] = True
            result['risk_contribution'] += 5
        
        # Check for hex encoding (phishers hide malicious paths)
        if '%' in url and len(re.findall(r'%[0-9A-Fa-f]{2}', url)) > 5:
            result['has_hex_encoding'] = True
            result['risk_contribution'] += 10
        
        # Check for risky TLDs
        for tld in RISKY_TLDS:
            if url.lower().endswith(tld):
                result['risky_tld'] = True
                result['risk_contribution'] += 15
                break
        
        # Check for @ symbol (used for URL trickery)
        if '@' in url and url.index('@') > url.index('//') if '//' in url else True:
            result['risk_contribution'] += 25  # Very suspicious redirect trick
        
        # Cap risk contribution
        result['risk_contribution'] = min(result['risk_contribution'], 45)
        
        return result
    
    def get_risk_description(self, result):
        """Human-readable risk description"""
        risks = []
        
        if result['uses_ip']:
            risks.append("🚨 CRITICAL: Uses IP address instead of domain name")
        if result['is_too_long']:
            risks.append(f"⚠️ Unusually long URL ({result['length']} chars)")
        if result['suspicious_keywords_found']:
            keywords_str = ', '.join(result['suspicious_keywords_found'][:5])
            risks.append(f"⚠️ Suspicious keywords found: {keywords_str}")
        if result['subdomain_count'] >= 3:
            risks.append(f"⚠️ Excessive subdomains ({result['subdomain_count']}) - URL obfuscation attempt")
        if result['risky_tld']:
            risks.append("⚠️ Unusually cheap/risky TLD (.xyz, .top, etc.)")
        if result['has_multiple_dashes']:
            risks.append("⚠️ Multiple dashes in URL (obfuscation pattern)")
        if '@' in result['url']:
            risks.append("🚨 CRITICAL: @ symbol in URL - credential harvesting trick")
        
        if not risks:
            return "✅ URL structure appears normal"
        return "\n".join(risks)