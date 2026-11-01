from email.message import EmailMessage
from pathlib import Path

Path('samples').mkdir(exist_ok=True)

# 1. Fake phishing email
bad = EmailMessage()
bad['From'] = 'PayPal Support <support@paypa1-secure.top>'
bad['To'] = 'victim@example.com'
bad['Reply-To'] = 'helpdesk@mail-collector.example.net'
bad['Subject'] = 'URGENT: Your account is suspended - verify immediately'
bad['Authentication-Results'] = 'mx.example.com; spf=fail; dkim=fail; dmarc=fail'
bad.set_content('Verify your account: http://203.0.113.45/login')
bad.add_alternative("<p>Dear user,</p><p>Please <a href='http://bit.ly/3xAmple'>https://www.paypal.com/verify</a> now.</p>", subtype='html')
bad.add_attachment(b'MZ' + bytes(64), maintype='application', subtype='octet-stream', filename='invoice.pdf.exe')
Path('samples/phish_sample.eml').write_bytes(bad.as_bytes())

# 2. Normal email
good = EmailMessage()
good['From'] = 'Team Newsletter <news@example.com>'
good['To'] = 'you@example.com'
good['Subject'] = 'Weekly update'
good['Authentication-Results'] = 'mx.example.com; spf=pass; dkim=pass; dmarc=pass'
good.set_content('Here is our weekly update. Read more at https://example.com/blog')
Path('samples/clean_sample.eml').write_bytes(good.as_bytes())

# 3. Disguised executable
disguised = EmailMessage()
disguised['From'] = 'Accounts <accounts@example.com>'
disguised['To'] = 'you@example.com'
disguised['Subject'] = 'Invoice attached'
disguised.set_content('Please see the attached invoice.')
disguised.add_attachment(b'MZ' + bytes(64), maintype='application', subtype='pdf', filename='invoice.pdf')
Path('samples/disguised_sample.eml').write_bytes(disguised.as_bytes())

print('Samples created in samples/')
