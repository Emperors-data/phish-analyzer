# Phishing Email Analyzer

A Python command-line tool that triages a suspicious email (`.eml` file). It checks the headers, links and attachments for common phishing indicators, then prints a 0-100 risk score with a plain-English reason for every point added.

It uses only Python's standard library, and it **never opens links or runs attachments**. It only reads and hashes data.

## Why I built it

When someone reports a suspicious email, a SOC analyst repeats the same first steps: check who really sent it, look at where the links go, and fingerprint any attachment. This tool automates those first triage steps and makes the reasoning visible, so an analyst can see why an email was flagged rather than trusting a black-box score.

## Features

- **Header analysis:** Reply-To and Return-Path mismatches, failed SPF/DKIM/DMARC results, display name spoofing, urgency language in the subject
- **URL analysis:** raw IP links, link shorteners, punycode domains, abused TLDs, `@` tricks, non-HTTPS links, and links whose visible text does not match their real destination
- **Attachment analysis:** SHA-256 and MD5 hashes, dangerous file types, double extensions, macro-enabled Office files, archives, and files disguised as another type (detected via the Windows `MZ` signature)
- **Transparent scoring:** every finding has a category, a point value and a reason
- **Safe output:** URLs are defanged (`hxxp://example[.]com`) so they cannot be clicked by accident
- **JSON export** for use in other tools

## How it works

```
.eml file
   |
   v
parse (Python email library)
   |
   +--> header checks ----+
   +--> URL checks -------+--> findings --> score (0-100) --> verdict --> report
   +--> attachment checks +
```

Each check returns a list of findings in the same shape (`category`, `points`, `message`). The scorer adds up the points (capped at 100) and maps the total to a verdict:

| Score | Verdict |
|---|---|
| 60 and above | HIGH RISK - likely phishing |
| 30 to 59 | SUSPICIOUS - needs manual review |
| Below 30 | LOW RISK - no strong indicators |

## Project structure

```
phish-analyzer/
  analyzer/
    common.py        finding format and URL defanging
    headers.py       header checks
    urls.py          link checks
    attachments.py   hashing and file checks
    scoring.py       score and verdict
    report.py        console output
  tools/make_samples.py   generates harmless test emails
  tests/test_analyzer.py  unit tests
  samples/                sample .eml files
  main.py                 command-line entry point
```

## Installation and usage

Requires Python 3.8 or newer. There are no dependencies to install for the tool itself.

```
git clone https://github.com/Emperors-Data/phish-analyzer.git
cd phish-analyzer
python3 tools/make_samples.py
python3 main.py samples/phish_sample.eml
```

Save the results as JSON too:

```
python3 main.py samples/phish_sample.eml --json out.json
```

Run the tests (needs `pip install pytest`), from the project root:

```
python -m pytest
```

## Example output

```
============================================================
PHISHING EMAIL ANALYSIS
============================================================
From:    PayPal Support <support@paypa1-secure.top>
Subject: URGENT: Your account is suspended - verify immediately
Score:   100 / 100
Verdict: HIGH RISK - likely phishing

FINDINGS
  +30 [attachment] Dangerous file type .exe: invoice.pdf.exe
  +25 [url] Link text shows hxxps://www[.]paypal[.]com/verify but goes to hxxp://bit[.]ly/3xAmple
  +20 [header] Reply-To domain (mail-collector.example.net) differs from From domain (paypa1-secure.top)
  +20 [header] Authentication failure: dmarc=fail
  +20 [url] Link uses a raw IP address: hxxp://203[.]0[.]113[.]45/login
  +20 [attachment] Double extension used to trick the user: invoice.pdf.exe
  +15 [header] Authentication failure: spf=fail
  +15 [header] Authentication failure: dkim=fail
  +15 [header] Display name mentions 'paypal' but the sender domain is paypa1-secure.top
  +10 [header] Urgency language in subject: ['urgent', 'immediately', 'suspended', 'verify']
  +10 [url] Link shortener hides the destination: hxxp://bit[.]ly/3xAmple
  +5 [url] Link is not HTTPS: hxxp://203[.]0[.]113[.]45/login
  +5 [url] Link is not HTTPS: hxxp://bit[.]ly/3xAmple

URLS (defanged)
   hxxp://203[.]0[.]113[.]45/login
   hxxp://bit[.]ly/3xAmple
   hxxps://www[.]paypal[.]com/verify

ATTACHMENTS
   invoice.pdf.exe - 66 bytes
     SHA256: 43e6bd75c30793dab0f2f6b58a757cddafb1df778f8b3af6be76ef1c76bbc2e5
     MD5:    50548103626d536108883b8953a1af1a
```

A normal email scores 0 with no findings:

```
Score:   0 / 100
Verdict: LOW RISK - no strong indicators
```

## Detection rules

| Category | Rule | Points | Why it matters |
|---|---|---|---|
| Header | Reply-To domain differs from From | 20 | Replies may go to an attacker-controlled address |
| Header | Return-Path domain differs from From | 10 | Mail may be sent through an unrelated system |
| Header | No Authentication-Results header | 5 | SPF/DKIM/DMARC could not be verified |
| Header | `spf=fail` | 15 | Sending server was not authorised for the domain |
| Header | `spf=softfail` | 10 | Sending server is probably not authorised |
| Header | `dkim=fail` | 15 | Signature is missing, invalid or message was altered |
| Header | `dmarc=fail` | 20 | Sender domain policy check failed |
| Header | Brand name in display name, different sender domain | 15 | Display name spoofing |
| Header | Urgency words in subject | 10 | Common pressure tactic |
| URL | Raw IP address in link | 20 | Legitimate services rarely link to bare IPs |
| URL | Link shortener | 10 | Hides the real destination |
| URL | Punycode (`xn--`) domain | 15 | Possible lookalike characters |
| URL | Frequently abused TLD | 10 | Cheap domains favoured by attackers |
| URL | `@` in the link | 15 | Can disguise the real host |
| URL | Not HTTPS | 5 | Weak signal |
| URL | Many subdomains | 5 | Used to make a fake domain look real |
| URL | Link text shows a different domain than the link target | 25 | Deliberate deception |
| Attachment | Dangerous file type | 30 | Executable or script content |
| Attachment | Double extension (e.g. `invoice.pdf.exe`) | 20 | Tricks users about the real file type |
| Attachment | Macro-enabled Office file | 20 | Common malware delivery method |
| Attachment | Archive | 10 | Can hide contents from scanners |
| Attachment | File starts with `MZ` but is not named `.exe` or `.dll` | 25 | File is disguised as another type |

## Safety design

- Links are never opened and no network requests are made.
- Attachments are never executed or opened, only read as bytes and hashed.
- URLs in the report are defanged.
- The included samples are harmless: the "executable" is the letters `MZ` followed by zeros.
- Test with real phishing samples only inside an isolated VM, and never commit real malware to this repository.

## Limitations

- Rule-based scoring, so the weights and thresholds are my own judgement and need tuning on real data.
- It trusts the `Authentication-Results` header, which is added by the receiving server. In a real environment only the header added by your own mail gateway should be trusted.
- No live reputation checks (VirusTotal, domain age, blocklists).
- The sender's own domain is not checked against the risky-TLD list, only links in the body.
- Cannot see links hidden in images or QR codes, or inside password-protected archives.
- Keyword lists are English-only.
- A compromised legitimate mailbox can pass SPF and DKIM, so this is triage support, not a final verdict.

## Future work

- Parse the `Received` chain to trace the path the message took
- Lookalike domain detection (for example `paypa1` vs `paypal`) using edit distance
- Hash and URL lookups against a threat-intelligence API
- Batch mode for a folder of emails and an HTML or Markdown report
- Compare the rule-based score with a small machine learning classifier

## What I learned

- Building this taught me how phishing detection works in practice: SPF, DKIM and DMARC results, Reply-To and display name mismatches, and links whose visible text hides the real destination.
- I chose a rule-based scoring model on purpose, because every point has a stated reason and an analyst can see exactly why an email was flagged. A trained model would be harder to explain.
- Testing showed me the difference between what a rule checks and what I assumed it checked. For example, the risky-TLD rule only looks at links in the body, not the sender's domain, and the disguised-file check only fires when a file's name does not match its content. I listed these gaps as limitations.
- Debugging taught me to read tracebacks from the bottom up. For example, I misspelled `urllib` as `urlib`, and `py_compile` did not catch it because it only checks syntax, not whether imports exist. After that I started importing every module in one command to check them. I also learned to run pytest from the project root so Python can find the `analyzer` package.
- Next I want to add lookalike-domain detection and threat-intelligence lookups for hashes.
