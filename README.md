# SpoofZero

**SpoofZero v1.0.0-rc1** is a local email-forensics workbench for raw .EML
evidence. It combines MIME parsing, sender and reported-authentication analysis,
IOC and attachment hashing, SMTP relay reconstruction, optional infrastructure
intelligence, deterministic evidence fusion, campaign correlation, versioned
cases, and integrity-verifiable forensic reports.

## Features

- Raw .EML and resilient multipart/HTML parsing
- Reported SPF, DKIM, DMARC identity and alignment analysis
- Sender mismatch, IOC, relay, origin-IP, and attachment-hash evidence
- Optional DNS, RDAP, geolocation, and VirusTotal enrichment
- Deterministic fusion with a reconciled contribution ledger
- Versioned cases, history comparison, campaign correlation, and reports

The bundled legacy text classifier is **EXPERIMENTAL / NOT VALIDATED**. Its score
is a supporting model signal, not a confirmed phishing probability. Under
<code>validated_evidence_fusion_v2</code> it contributes exactly zero numeric
risk points.

## Quick start

Python 3.11 or newer is required; Python 3.12 is recommended.

~~~bash
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run_spoofzero.py --check
python run_spoofzero.py
~~~

Open <http://127.0.0.1:8501>. The helper uses argument-list process launching,
binds to localhost by default, checks model/storage readiness, and works from the
repository location regardless of the caller's current directory.

For a network-free presentation:

~~~bash
python run_spoofzero.py --demo
~~~

Then open **Explore with safe built-in evidence** and choose a scenario. Demo
analysis uses maintained repository samples and never contacts DNS, RDAP,
VirusTotal, or geolocation services. Those results are shown as unavailable,
never as successful or safe.

## Investigation workflow

1. Upload an .EML file, or choose built-in demo evidence.
2. Analyze and review the forensic score, authentication, identity, relay, IOCs,
   attachment hashes, and clearly labeled optional intelligence.
3. Create or select a case, then save the result as an immutable snapshot.
4. Reanalyze to append a version; compare history without recalculating it.
5. Correlate shared senders, URLs, domains, IPs, hashes, and infrastructure.
6. Export integrity-verifiable JSON or printable HTML from the case workspace.

Raw email bodies and attachment payloads are not retained in case snapshots.
Standard snapshots may contain personal message metadata; enable privacy-safe
storage to minimize it. SQLite storage is local and unencrypted at rest.

## Configuration and operations

Copy [.env.example](.env.example) to .env and add local values. A VirusTotal key
is optional. Missing, disabled, timed-out, or failed services produce
<code>UNKNOWN</code>/<code>UNAVAILABLE</code> evidence and never imply safety.

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Safe demo walkthrough](docs/demo-walkthrough.md)
- [Deployment options](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Release readiness](docs/release-readiness.md)
- [Architecture](docs/architecture.md)
- [Security and privacy model](docs/security-privacy-performance-hardening.md)
- [Forensic scoring and calibration](docs/risk-score-calibration.md)

Run the offline suite with:

~~~bash
python -m unittest discover -s tests -v
~~~

## Release-candidate limits

SpoofZero does not independently perform SMTP-time SPF, DKIM, or DMARC
verification; it parses reported historical results and keeps current DNS policy
separate. Correlation supports investigation but does not prove shared authorship.
IP geolocation estimates infrastructure location and does not locate a person.
The app has no built-in user authentication, authorization, encrypted database,
or multi-user isolation, so unrestricted public deployment is not approved.
