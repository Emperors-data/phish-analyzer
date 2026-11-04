import sys
from pathlib import Path
from analyzer.headers import load_email, analyze_headers
from analyzer.urls import analyze_urls
from analyzer.attachments import analyze_attachments
from analyzer.scoring import calculate_score

folder = Path(sys.argv[1]).expanduser()
files = sorted(folder.rglob('*.eml'))
flagged = []

for path in files:
    try:
        msg = load_email(path)
        findings = analyze_headers(msg) + analyze_urls(msg)[0] + analyze_attachments(msg)[0]
    except Exception as e:
        print('ERROR', path.name, e)
        continue
    score = calculate_score(findings)
    if score >= 20:
        flagged.append((score, path.name, findings))

print(f'Checked {len(files)} legitimate emails')
for t in (20, 30, 60):
    print(f'score >= {t}: {sum(1 for s, _, _ in flagged if s >= t)}')

print()
for score, name, findings in sorted(flagged, reverse=True):
    print(score, name)
    for f in sorted(findings, key=lambda x: -x['points']):
        print('   +%d %s' % (f['points'], f['message']))
