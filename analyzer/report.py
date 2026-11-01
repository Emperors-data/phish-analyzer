from analyzer.common import defang

def print_report(result):
    r = result
    line = '=' * 60
    print(line)
    print('PHISHING EMAIL ANALYSIS')
    print(line)
    print('From:   ', r['from'])
    print('Subject:', r['subject'])
    print('Score:  ', r['score'], '/ 100')
    print('Verdict:', r['verdict'])
    print()
    print('FINDINGS')
    if not r['findings']:
        print('  none')
    for f in sorted(r['findings'], key=lambda x: -x['points']):
        print('  +%d [%s] %s' % (f['points'], f['category'], f['message']))
    print()
    print('URLS (defanged)')
    for u in r['urls']:
        print('  ', defang(u))
    print()
    print('ATTACHMENTS')
    for a in r['attachments']:
        print('  ', a['filename'], '-', a['size_bytes'], 'bytes')
        print('     SHA256:', a['sha256'])
        print('     MD5:   ', a['md5'])
