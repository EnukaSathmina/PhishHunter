#!/usr/bin/env python3
# run.py - Improved runner with better error handling

import sys
import os
import warnings
warnings.filterwarnings('ignore')  # Suppress SSL warnings in output

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from detector import PhishingDetector

def print_banner():
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║   🔗 PHISHING DETECTION TOOL v2.0 - IMPROVED         ║
    ║   - Domain Age (with dead domain detection)          ║
    ║   - SSL Certificate Validation                       ║
    ║   - URL Pattern Analysis                             ║
    ║   - DNS Resolution Check                             ║
    ╚═══════════════════════════════════════════════════════╝
    """)

def test_dead_domains():
    """Test URLs that are known dead/phishing"""
    dead_urls = [
        ("https://paypal.com.login-secure.xyz/login/verify/", "Dead Phishing Domain"),
        ("https://amazon-account-verify.tk/signin", "Dead Typosquat Domain"),
    ]
    
    print("\n🧪 TESTING KNOWN DEAD/PHISHING DOMAINS")
    print("="*60)
    
    detector = PhishingDetector(verbose=True)
    
    for url, description in dead_urls:
        print(f"\n📌 Testing: {description}")
        report = detector.detect(url)
        print(f"\n{'='*50}")
        print(f"VERDICT: {report['verdict_icon']} {report['verdict']}")
        print(f"RISK SCORE: {report['risk_score']}/100")
        print(f"DOMAIN EXISTS: {report['checks']['domain_age'].get('domain_exists', 'Unknown')}")
        print(f"{'='*50}")

def live_test():
    """Test with URLs you provide interactively"""
    print("\n🎯 INTERACTIVE MODE")
    print("Enter URLs to test (type 'quit' to exit)")
    print("-"*50)
    
    detector = PhishingDetector(verbose=True)
    
    while True:
        url = input("\n🔗 Enter URL (with http:// or https://): ").strip()
        if url.lower() in ['quit', 'exit', 'q']:
            break
        if not url:
            continue
        if not url.startswith(('http://', 'https://')):
            print("⚠️ URL must start with http:// or https://")
            continue
        
        report = detector.detect(url)
        print(f"\n{'='*55}")
        print(f"VERDICT: {report['verdict_icon']} {report['verdict']}")
        print(f"RISK SCORE: {report['risk_score']}/100")
        print(f"\nDETAILS:")
        print(report['summary'])
        print(f"{'='*55}")

def main():
    print_banner()
    
    if len(sys.argv) > 1:
        # Command line mode
        url = sys.argv[1]
        detector = PhishingDetector(verbose=True)
        report = detector.detect(url)
        print(f"\n{'='*55}")
        print(f"VERDICT: {report['verdict_icon']} {report['verdict']}")
        print(f"RISK SCORE: {report['risk_score']}/100")
        print(f"\n{report['summary']}")
        print(f"{'='*55}")
    else:
        # Interactive menu
        print("\nCHOOSE A MODE:")
        print("1. Test with built-in suspicious URLs")
        print("2. Interactive mode (enter your own URLs)")
        print("3. Run original demo")
        
        choice = input("\nEnter choice (1/2/3): ").strip()
        
        if choice == '1':
            test_dead_domains()
        elif choice == '2':
            live_test()
        else:
            from detector import demo_detection
            demo_detection()

if __name__ == "__main__":
    main()