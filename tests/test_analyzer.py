from email.message import EmailMessage
from analyzer.attachments import analyze_attachments
from analyzer.urls import analyze_urls


def test_double_extension_flagged():
    msg = EmailMessage()
    msg.set_content('hi')
    msg.add_attachment(b'abc', maintype='application', subtype='octet-stream', filename='report.pdf.exe')
    findings, attachments = analyze_attachments(msg)
    assert any('Double extension' in f['message'] for f in findings)
    assert len(attachments[0]['sha256']) == 64


def test_link_text_mismatch_flagged():
    msg = EmailMessage()
    msg.set_content('hi')
    msg.add_alternative("<a href='http://evil.example.net/x'>https://www.paypal.com</a>", subtype='html')
    findings, urls = analyze_urls(msg)
    assert any('Link text shows' in f['message'] for f in findings)
