import ipaddress
import re
from html.parser import HTMLParser
from urlib.parse import urlparse
from analyzer.common import make_finding, defang

URL_RE = re.compile(r'https?://[^\s<>"\x27]+', re.IGNORECASE)
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt,ly'}
RISKY_TLDS = ('.top', '.xyz', '.click', '.tk', '.gq', '.ml', '.cf', '.zip')

class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []
        
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self._href = dict(attrs).get('href')
            self._text = []
            
    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
            
    def handle_endtag(self, tag):
        if tag == 'a' and self._href is not None:
            self.links.append((self._href, ''.join(self._text).strip()))
            self._href = None
         
def extract_bodies(msg):
    plain, html = '', ''
    for part in msg.walk():
        if part.is_attachment():
            continue
        kind = part.get_content_type()
        try:
            if kind == 'text/plain':
                plain += part.get_content()
            elif kind == 'text/html':
                html += part.get_content()
        except Exception:
            continue
    return plain, html
    
def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
        
def host_of(url):
    findings = []
    parsed = urlparse(url)
    host = (parsed.hostname or '').lower()
    safe = defang(url)
    
    if is_ip(host):
        findings.append(make_finding('url', 20, f'Link uses a raw IP address: {safe}'))
    if host in SHORTENERS:
        findings.append(make_finding('url', 10, f'Link shortener hides the destination: {safe}'))
    if 'xn--' in host:
        findings.append(make_finding('url', 15, f'Punycode domain (possible lookalike): {safe}'))
    if host.endswith(RISKY_TLDS):
        findings.append(make_finding('url', 10, f'Frequently abused top-level domain: {safe}'))
    if '@' in parsed.netloc:
        findings.append(make_finding('url', 15, f'Link contains an @ to disguise the real host: {safe}'))
    if parsed.scheme == 'http':
        findings.append(make_finding('url', 5, f'Link is not HTTPS: {safe}'))
    if host.count('.') >= 4:
        findings.append(make_finding('url', 5, f'Unusually many subdomains: {safe}'))
    return findings
    
def analyze_urls(msg):
    plain, html = extract_bodies(msg)
    collector = LinkCollector()
    collector.feed(html)
    
    found = {u.rstrip('.,;:)') for u in URL_RE.findall(plain + ' ' + html)}
    found |= {h for h, _ in collector.links if h and h.startswith(('http://', 'https://'))}
    
    findings = []
    for url in sorted(found):
        try:
            findings += check_url(url)
        except ValueError:
            continue
            
    for href, text in collector.links:
        if href and text.lower().startswith(('http://', 'https://', 'www.')) and href.startswith('http'):
           shown = text if '://' in text else 'http://' + text
           if host_of(shown) != host_of(href):
              findings.append(make_finding('url', 25,
                  f'Link text shows {defang(text)} but goes to {defang(href)}'))
               
    return findings, sorted(found)        
