# Troubleshooting

**Readiness reports NOT_READY**

Run <code>python run_spoofzero.py --check</code>. Confirm Python is at least 3.11,
the pinned legacy model/vectorizer files exist, and the configured case directory
is writable. The output intentionally omits local paths and secrets.

**A reputation or geolocation panel says unavailable**

This is a valid partial result. Check external-service switches, network access,
timeouts, and the optional VirusTotal key. An unavailable lookup never means the
indicator is safe.

**The app starts but cannot save a case**

Set SPOOFZERO_CASE_DB to a writable local path. Existing databases are migrated
with a backup and historical snapshots remain immutable. Do not place the
database in Git.

**A large or malformed email is rejected**

The parser enforces bounded email, MIME, body, and attachment limits. Preserve
the original evidence separately and inspect why it exceeds the safety limits;
do not weaken the limits for public input.

**A demo unexpectedly appears to need the network**

Stop the process and restart with <code>python run_spoofzero.py --demo</code>.
The UI must label DNS, RDAP, VirusTotal, and geolocation evidence unavailable.

**The AI score looks confident**

It is an experimental, unvalidated model signal. It is supporting evidence only
and contributes zero numeric points under the current fusion policy.
