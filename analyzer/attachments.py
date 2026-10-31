import hashlib
from pathlib import Path
from analyzer.common import make_finding

DANGEROUS = {'.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1',
             '.jar', '.hta', '.lnk', '.iso'}
MACRO_OFFICE = {'.docm', '.xlsm', '.pptm'}
ARCHIVES = {'.zip', '.rar', '.7z'}


def analyze_attachments(msg):
    findings, attachments = [], []
    for part in msg.iter_attachments():
        name = part.get_filename() or '(no name)'
        data = part.get_payload(decode=True) or b''
        suffixes = [s.lower() for s in Path(name).suffixes]
        ext = suffixes[-1] if suffixes else ''

        attachments.append({
            'filename': name,
            'size_bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'md5': hashlib.md5(data).hexdigest(),
        })

        if ext in DANGEROUS:
            findings.append(make_finding('attachment', 30, f'Dangerous file type {ext}: {name}'))
            if len(suffixes) >= 2:
                findings.append(make_finding('attachment', 20, f'Double extension used to trick the user: {name}'))
        if ext in MACRO_OFFICE:
            findings.append(make_finding('attachment', 20, f'Macro-enabled Office file: {name}'))
        if ext in ARCHIVES:
            findings.append(make_finding('attachment', 10, f'Archive can hide its contents from scanners: {name}'))
        if data.startswith(b'MZ') and ext not in {'.exe', '.dll'}:
            findings.append(make_finding('attachment', 25, f'File starts with the Windows executable signature (MZ) but is named {name}'))

    return findings, attachments
