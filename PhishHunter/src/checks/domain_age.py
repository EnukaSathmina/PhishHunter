# src/checks/domain_age.py - COMPLETELY REWRITTEN FOR COMPATIBILITY

import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
import socket
import re

class DomainAgeChecker:
    """
    Checks domain age using WHOIS lookup.
    Handles ALL TLDs gracefully without crashing.
    """
    
    def __init__(self):
        self.results = {}
    
    def extract_domain(self, url):
        """Extract domain from URL - removes subdomains for WHOIS"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        domain = domain.lower()
        
        # Remove www. prefix for cleaner WHOIS
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    
    def domain_resolves(self, domain):
        """Check if domain actually resolves to an IP"""
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
    
    def safe_whois_lookup(self, domain):
        """
        Safely perform WHOIS lookup without crashing on any TLD.
        Returns dict with results or None on failure.
        """
        try:
            # Try the WHOIS lookup
            w = whois.whois(domain)
            
            # Handle the case where w is None or empty
            if not w:
                return None
                
            return w
            
        except Exception as e:
            # Catch ANY exception - this library throws different errors on different systems
            error_msg = str(e)
            
            # Common error patterns
            if "No match for" in error_msg or "not found" in error_msg.lower():
                # Domain doesn't exist or isn't registered
                return {'error': 'domain_not_registered'}
            elif "command returned no output" in error_msg.lower():
                # WHOIS server doesn't respond for this TLD
                return {'error': 'whois_no_output'}
            elif "connection refused" in error_msg.lower():
                return {'error': 'connection_refused'}
            elif "timed out" in error_msg.lower():
                return {'error': 'timeout'}
            else:
                return {'error': f'unknown: {error_msg[:100]}'}
    
    def extract_creation_date(self, whois_data):
        """Extract creation date from WHOIS data regardless of format"""
        if not whois_data:
            return None
            
        # Try different possible field names
        date_fields = ['creation_date', 'created', 'registration_date', 'reg_date']
        
        for field in date_fields:
            if hasattr(whois_data, field):
                date_val = getattr(whois_data, field)
                if date_val:
                    # Handle list case
                    if isinstance(date_val, list):
                        date_val = date_val[0]
                    # Handle string case
                    if isinstance(date_val, str):
                        try:
                            # Try common date formats
                            for fmt in ['%Y-%m-%d', '%d-%b-%Y', '%Y.%m.%d', '%d/%m/%Y']:
                                try:
                                    return datetime.strptime(date_val, fmt)
                                except:
                                    continue
                        except:
                            pass
                    # Handle datetime object
                    if isinstance(date_val, datetime):
                        return date_val
        return None
    
    def check(self, url):
        """Main check method - handles all errors gracefully"""
        domain = self.extract_domain(url)
        
        result = {
            'domain': domain,
            'registered': None,
            'age_days': None,
            'is_new': False,
            'is_very_new': False,
            'domain_exists': self.domain_resolves(domain),
            'risk_contribution': 0,
            'error': None,
            'whois_available': True
        }
        
        # If domain doesn't resolve at all, it's suspicious
        if not result['domain_exists']:
            result['error'] = f"Domain '{domain}' does not resolve (no DNS record)"
            result['risk_contribution'] = 40
            result['whois_available'] = False
            return result
        
        # Perform WHOIS lookup safely
        whois_result = self.safe_whois_lookup(domain)
        
        # Handle WHOIS failures
        if not whois_result:
            result['whois_available'] = False
            result['error'] = "WHOIS lookup returned no data"
            result['risk_contribution'] = 15  # Slightly suspicious but not critical
            return result
        
        # Check if we got an error dict
        if isinstance(whois_result, dict) and 'error' in whois_result:
            result['whois_available'] = False
            error_type = whois_result['error']
            
            if error_type == 'domain_not_registered':
                result['error'] = "Domain appears to be unregistered or invalid"
                result['risk_contribution'] = 45  # Very suspicious
            elif error_type == 'whois_no_output':
                result['error'] = f"WHOIS not available for .{domain.split('.')[-1]} TLD"
                result['risk_contribution'] = 10  # Some TLDs just don't support WHOIS
            else:
                result['error'] = f"WHOIS lookup failed: {error_type}"
                result['risk_contribution'] = 15
            return result
        
        # Extract creation date
        creation_date = self.extract_creation_date(whois_result)
        
        if creation_date:
            result['registered'] = creation_date.strftime('%Y-%m-%d')
            
            # Calculate age
            now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
            if creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            
            age_delta = now - creation_date
            result['age_days'] = age_delta.days
            
            # Risk assessment based on age
            if result['age_days'] < 7:
                result['is_very_new'] = True
                result['risk_contribution'] = 35
            elif result['age_days'] < 30:
                result['is_new'] = True
                result['risk_contribution'] = 20
            else:
                result['risk_contribution'] = 0
        else:
            result['error'] = "Could not extract creation date from WHOIS"
            result['risk_contribution'] = 15
        
        return result
    
    def get_risk_description(self, result):
        """Human-readable risk description"""
        if not result['domain_exists']:
            return f"🚨 CRITICAL: Domain '{result['domain']}' has no DNS records - FAKE DOMAIN!"
        
        if result.get('error'):
            error_msg = result['error']
            
            if "WHOIS not available" in error_msg:
                tld = result['domain'].split('.')[-1]
                return f"ℹ️ WHOIS unavailable for .{tld} domains - Cannot verify age (normal for some TLDs)"
            elif "not resolve" in error_msg:
                return f"🚨 Domain '{result['domain']}' does not exist - FAKE!"
            elif "unregistered" in error_msg:
                return f"🚨 Domain '{result['domain']}' appears unregistered - FAKE PHISHING DOMAIN!"
            else:
                return f"⚠️ Domain age unknown: {error_msg[:80]}"
        
        if result['is_very_new']:
            return f"🚨 CRITICAL: Domain registered ONLY {result['age_days']} days ago (< 7 days) - EXTREMELY suspicious for a bank!"
        if result['is_new']:
            return f"⚠️ Domain registered {result['age_days']} days ago (< 30 days) - Unusually new for a financial site"
        if result['age_days']:
            return f"✅ Domain registered {result['age_days']} days ago - Normal age"
        
        return f"ℹ️ Domain age could not be determined"