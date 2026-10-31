import argparse
import json
from analyzer.headers import load_email, analyze_headers
from analyzer.urls import analyze_urls
from analyzer.attachments import analyze_attachments
from analyzer.scoring import calculate_score, verdict
from analyzer.report import print_report


def main():
    parser = argparse.ArgumentParser(description='Analyze a .eml file for phishing indicators')
    parser.add_argument('email_file', help='path to a .eml file')
    parser.add_argument('--json', help='save the results to this JSON file')
    args = parser.parse_args()

    msg = load_email(args.email_file)
    url_findings, urls = analyze_urls(msg)
    att_findings, attachments = analyze_attachments(msg)
    findings = analyze_headers(msg) + url_findings + att_findings
    score = calculate_score(findings)

    result = {
        'from': str(msg.get('From', '')),
        'subject': str(msg.get('Subject', '')),
        'score': score,
        'verdict': verdict(score),
        'findings': findings,
        'urls': urls,
        'attachments': attachments,
    }
    print_report(result)
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(result, f, indent=2)


if __name__ == '__main__':
    main()
