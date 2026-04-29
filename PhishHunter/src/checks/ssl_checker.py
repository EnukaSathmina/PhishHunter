# src/checks/ssl_checker.py - CLEANED VERSION

import ssl
import socket
from datetime import datetime

class SSLChecker:
    
    def __init__(self):
        self.results = {}
    
    def extract_hostname(self, url):
        import re
        hostname = re.sub(r'^https?://', '', url)
        hostname = hostname.split('/')[0]
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        return hostname
    
    def check(self, url):
        hostname = self.extract_hostname(url)
        result = {
            'hostname': hostname,
            'has_ssl': False,
            'is_valid': False,
            'issuer': None,
            'expiry_days': None,
            'risk_contribution': 0,
            'error': None,
            'port_open': False
        }
        
        # Check if port 443 is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result['port_open'] = sock.connect_ex((hostname, 443)) == 0
            sock.close()
        except:
            result['port_open'] = False
        
        if not result['port_open']:
            result['error'] = "Port 443 closed - No HTTPS"
            result['risk_contribution'] = 25
            return result
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['has_ssl'] = True
                    result['is_valid'] = True
                    
                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    # Expiry
                    expiry_str = cert['notAfter']
                    expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    result['expiry_days'] = (expiry - datetime.now()).days
                    
                    result['risk_contribution'] = 0
                    
        except socket.timeout:
            result['error'] = "Connection timeout"
            result['risk_contribution'] = 15
        except ssl.SSLCertVerificationError:
            result['error'] = "SSL certificate verification failed"
            result['risk_contribution'] = 25
        except Exception as e:
            result['error'] = str(e)[:80]
            result['risk_contribution'] = 15
            result['has_ssl'] = False
        
        return result
    
    def get_risk_description(self, result):
        if result.get('error'):
            if "Port 443 closed" in result['error']:
                return "⚠️ No HTTPS - Your data would be sent in plain text!"
            return f"⚠️ SSL Error: {result['error']}"
        if not result.get('has_ssl'):
            return "❌ No valid SSL certificate - DANGEROUS"
        if result['expiry_days'] and result['expiry_days'] < 0:
            return f"❌ SSL certificate EXPIRED {abs(result['expiry_days'])} days ago"
        if result['expiry_days'] and result['expiry_days'] < 30:
            return f"⚠️ SSL certificate expires in {result['expiry_days']} days"
        return f"✅ Valid SSL from {result['issuer']}, expires in {result['expiry_days']} days"