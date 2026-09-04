# Deployment options

## Local workstation

<code>python run_spoofzero.py</code> is the recommended mode. It binds to
127.0.0.1 by default. Keep the case database on a user-controlled local volume
and restrict filesystem permissions.

## Controlled private deployment

A private deployment is **CONDITIONAL**. Put SpoofZero behind HTTPS and an
authenticated reverse proxy, restrict it to trusted investigators, mount a
persistent protected volume at /data, and manage VT_API_KEY in the platform
secret store.

A container definition is included for reproducibility:

~~~bash
docker build -t spoofzero:1.0.0-rc1 .
docker run --rm -p 127.0.0.1:8501:8501 \
  -v spoofzero-data:/data \
  --env-file .env spoofzero:1.0.0-rc1
~~~

The image runs as an unprivileged user and exposes the Streamlit health endpoint.
The application readiness command is
<code>python run_spoofzero.py --check</code>. No image is published and no
deployment is performed by this repository.

Before any controlled private deployment, the operator must provide:

| Control | Requirement |
| --- | --- |
| Runtime | Python 3.12 recommended; install the pinned requirements |
| Persistence | Protected persistent volume for SPOOFZERO_CASE_DB; never ephemeral container storage |
| Transport | HTTPS termination at a maintained reverse proxy |
| Identity | Authentication and role-based authorization outside the app |
| Upload boundary | Keep the application 10 MiB .EML limit; set the proxy limit no higher |
| Abuse controls | Per-user request rate limits, bounded concurrency, and upload quotas |
| Isolation | Separate trusted teams or tenants; the app has no native tenant boundary |
| Retention/deletion | Written evidence retention, deletion, legal-hold, and user-notification rules |
| Secrets | Platform secret manager; never image layers, source, logs, or plain deployment files |
| Monitoring | Health monitoring and security event collection without bodies, keys, or raw evidence |
| Backup/restore | Consistent SQLite volume backups, protected copies, and tested restore procedures |
| Database | SQLite is suitable only for a small controlled workload; assess a production store before scaling |
| External services | Explicit opt-in, provider terms/privacy review, bounded timeouts, and failure monitoring |

## Unrestricted public deployment

Readiness is **NO**. The application does not include native authentication,
authorization, tenant isolation, encrypted case storage, a production database,
centralized audit retention, or a public abuse-control layer. Do not expose it
directly to the internet.

## External-service and privacy notes

Demo mode disables all live services. Local mode can call configured DNS, RDAP,
geolocation, and VirusTotal endpoints when a user analyzes evidence. Attachments
are represented to VirusTotal only by SHA-256 hashes; payloads are never
automatically uploaded. Extracted URLs are never automatically opened. Service
failure remains unknown, never safe. Review each provider's terms and
data-handling policy before enabling calls with sensitive evidence.
