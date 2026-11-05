import sys
from pathlib import Path
from analyzer.headers import load_email, analyze_headers
from analyzer.urls import analyze_urls
from analyzer.attachments import analyze_attachments
from analyzer.scoring import calculate_score

folder = Path(sys.argv[1])
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 100
scores = []
start = int(sys.argv[3]) if len(sys.argv) > 3 else 0
for path in sorted(folder.glob('*.eml'))[start:start + limit]:
    try:
        msg = load_email(path)
        findings = analyze_headers(msg) + analyze_urls(msg)[0] + analyze_attachments(msg)[0]
        scores.append(calculate_score(findings))
    except Exception as e:
        print('ERROR', path.name, e)

total = len(scores)
for t in (20, 30, 60):
    print(f'score >= {t}: {sum(s >= t for s in scores)} of {total}')
