# detector.py
import time
from urllib.parse import urlparse
from checks.domain_age import DomainAgeChecker
from checks.ssl_checker import SSLChecker
from checks.url_analyzer import URLAnalyzer

class PhishingDetector:
    """
    Main orchestrator that combines all detection methods.
    Produces final risk score and verdict.
    """
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.domain_age_checker = DomainAgeChecker()
        self.ssl_checker = SSLChecker()
        self.url_analyzer = URLAnalyzer()
        
        # Weight multipliers for final score
        self.weights = {
            'domain_age': 1.0,
            'ssl': 1.0,
            'url_patterns': 1.2  # URL patterns weighted slightly higher
        }
    
    def validate_url(self, url):
        """Basic URL validation"""
        if not url:
            return False, "Empty URL provided"
        if not url.startswith(('http://', 'https://')):
            return False, "URL must start with http:// or https://"
        return True, None
    
    def detect(self, url):
        """
        Run full detection pipeline on a URL.
        Returns comprehensive analysis results.
        """
        # Validate
        is_valid, error = self.validate_url(url)
        if not is_valid:
            return {'error': error, 'verdict': 'INVALID'}
        
        # Run all checks
        print(f"\n🔍 Analyzing: {url}\n{'='*50}") if self.verbose else None
        
        domain_age_result = self.domain_age_checker.check(url)
        ssl_result = self.ssl_checker.check(url)
        url_result = self.url_analyzer.check(url)
        
        # Calculate weighted risk score (0-100)
        raw_score = (
            domain_age_result.get('risk_contribution', 0) * self.weights['domain_age'] +
            ssl_result.get('risk_contribution', 0) * self.weights['ssl'] +
            url_result.get('risk_contribution', 0) * self.weights['url_patterns']
        )
        
        # Normalize to 0-100
        max_possible = 35 + 40 + 54  # Max from each check after weights (approx)
        final_score = min(int((raw_score / max_possible) * 100), 100)
        
        # Determine verdict
        if final_score >= 80:
            verdict = "DANGEROUS"
            verdict_icon = "🔴"
        elif final_score >= 60:
            verdict = "HIGH RISK"
            verdict_icon = "🟠"
        elif final_score >= 40:
            verdict = "SUSPICIOUS"
            verdict_icon = "🟡"
        elif final_score >= 20:
            verdict = "LOW RISK"
            verdict_icon = "🟢"
        else:
            verdict = "SAFE"
            verdict_icon = "✅"
        
        # Compile full report
        report = {
            'url': url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'risk_score': final_score,
            'verdict': verdict,
            'verdict_icon': verdict_icon,
            'checks': {
                'domain_age': domain_age_result,
                'ssl': ssl_result,
                'url_patterns': url_result
            },
            'summary': self._generate_summary(domain_age_result, ssl_result, url_result, final_score)
        }
        
        return report
    
    def _generate_summary(self, domain_age, ssl, url_patterns, final_score):
        """Generate a human-readable summary"""
        summary_lines = []
        
        if final_score >= 70:
            summary_lines.append("🚨 This URL shows strong indicators of a phishing attempt!")
        elif final_score >= 40:
            summary_lines.append("⚠️ This URL has suspicious characteristics. Proceed with caution.")
        else:
            summary_lines.append("✅ This URL appears legitimate based on our checks.")
        
        summary_lines.append("")
        summary_lines.append(self.domain_age_checker.get_risk_description(domain_age))
        summary_lines.append(self.ssl_checker.get_risk_description(ssl))
        summary_lines.append(self.url_analyzer.get_risk_description(url_patterns))
        
        return "\n".join(summary_lines)


def demo_detection():
    """Demo function to test the detector with sample URLs"""
    detector = PhishingDetector(verbose=True)
    
    test_urls = [
        "https://www.google.com",
        "https://paypal.com.login-secure.xyz/login/verify/account/?id=123456",
        "https://amazon-account-verify.tk/signin",
        "https://github.com"
    ]
    
    for url in test_urls:
        report = detector.detect(url)
        print(f"\n📊 {'='*50}")
        print(f"{report['verdict_icon']} VERDICT: {report['verdict']}")
        print(f"📈 RISK SCORE: {report['risk_score']}/100")
        print(f"📝 {report['summary']}")
        print(f"{'='*50}\n")

if __name__ == "__main__":
    demo_detection()