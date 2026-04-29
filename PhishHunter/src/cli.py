# cli.py
import argparse
import sys
from detector import PhishingDetector

def main():
    parser = argparse.ArgumentParser(
        description='Phishing Detection Tool - Analyze URLs for phishing indicators'
    )
    parser.add_argument('url', help='URL to analyze (must include http:// or https://)')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress verbose output')
    
    args = parser.parse_args()
    
    detector = PhishingDetector(verbose=not args.quiet)
    report = detector.detect(args.url)
    
    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print(f"\n📊 ANALYSIS REPORT")
        print(f"{'='*50}")
        print(f"URL: {report['url']}")
        print(f"Timestamp: {report['timestamp']}")
        print(f"Risk Score: {report['risk_score']}/100")
        print(f"Verdict: {report['verdict_icon']} {report['verdict']}")
        print(f"\n{report['summary']}")

if __name__ == "__main__":
    main()