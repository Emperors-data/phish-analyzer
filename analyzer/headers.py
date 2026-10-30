from emails import policy
from email.parser import BytesParser
from email.utils import parseaddr
from analyzer.common import make_finding

BRANDS = ['paypal', 'microsoft', 'amazon', 'apple', 'google',
          'netflix', 'sbi', 'hdfc', 'icici']
URGENT_WORDS = ['urgent', 'immediately', 'suspended', 'verify',
                'action required', 'password', 'final notice']
                
def load_email(path):
    with open(path, 'rb') as f:
        return BytesParser(policy=policy.default).parse(f)
        
def domain_of(header_value):
    address = parseaddr(str(header_value or ''))[1]
    return address.split('@')[-1].lower() if '@' in address else ''

def analyze_headers(msg):
    findings = []
    from_domain = domain_of(msg.get('From'))
    reply_domain = domain_of(msg.get('Reply-To'))
    path_domain = domain_of(msg.get('Return-Path'))
    display_name = parseaddr(str(msg.get('From', '')))[0].lower()
    subject = str(msg.get('Subject') or '').lower()
    auth = str(msg.get('Authentication-Results') or '').lower()
    
    if reply_domain and reply_domain != from_domain:
        findings.append(make_finding('header', 20,
            f'Return-Path domain ({reply_domain}) differs from From    domain ({from_domain})'))
            
    if path_domain and path_domain != from_domain:
        findings.append(make_finding('header', 10,
            f'Return-Path domain ({path_domain}) differs from From domain ({from_domain})'))
            
    if not auth:
        findings.append(make_finding('header', 5,
            'No Authentication-Results header, so SPF/DKIM/DMARC could not be checked'))
    else:
        checks = [('spf=fail', 15), ('spf=softfail', 10),
                  ('dkim=fail', 15), ('dmarc=fail', 20)]
        for text, points in checks:
            if text in auth:
                findings.append(make_finding('header', points,
                    f'Authentication failure: {text}'))
    
    for brand in BRANDS:
        if brand in display_name and brand not in from_domain:
            findings.append(make_finding('header', 15,
                f'Display name mentions {brand!r} but the sender domain is {from_domain}'))
            break
     
    hits = [w for w in URGENT_WORDS if W in subject]
    if hits:
        findings.append(make_findings('header', 10,
            f'Urgency language in subject: {hits}'))
    
    return findings 
       
