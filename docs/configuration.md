# Configuration

Copy .env.example to .env. The local .env file is ignored by Git. Environment
variables take effect at process start.

| Setting | Default | Purpose |
| --- | ---: | --- |
| SPOOFZERO_MODE | local | demo disables every live external service |
| SPOOFZERO_CASE_DB | data/cases/spoofzero.sqlite3 | Local SQLite case path |
| SPOOFZERO_PRIVACY_SAFE_DEFAULT | false | Default metadata-minimization selection |
| SPOOFZERO_EXTERNAL_SERVICES_ENABLED | true | Master live-enrichment switch |
| SPOOFZERO_VIRUSTOTAL_ENABLED | true | Domain, IP, and SHA-256 reputation |
| SPOOFZERO_DNS_ENABLED | true | Current DNS intelligence |
| SPOOFZERO_RDAP_ENABLED | true | Current registration intelligence |
| SPOOFZERO_GEOLOCATION_ENABLED | true | Approximate infrastructure geolocation |
| VT_API_KEY | empty | Optional VirusTotal credential |
| SPOOFZERO_VT_TIMEOUT_SECONDS | 15 | VirusTotal request timeout |
| SPOOFZERO_DNS_TIMEOUT_SECONDS | 3 | Per-record DNS timeout |
| SPOOFZERO_RDAP_TIMEOUT_SECONDS | 8 | RDAP request timeout |
| SPOOFZERO_GEOLOCATION_TIMEOUT_SECONDS | 10 | Geolocation request timeout |
| SPOOFZERO_VT_CACHE_TTL_SECONDS | 300 | Successful VT in-memory cache life |
| SPOOFZERO_DNS_CACHE_TTL_SECONDS | 300 | DNS cache life |
| SPOOFZERO_RDAP_CACHE_TTL_SECONDS | 900 | RDAP cache life |
| SPOOFZERO_GEOLOCATION_CACHE_TTL_SECONDS | 900 | Geolocation cache life |
| SPOOFZERO_FAILURE_CACHE_TTL_SECONDS | 20 | Temporary failure cache life |

Boolean values accept true/false, yes/no, on/off, or 1/0. Invalid values fall back
to bounded defaults and appear in the readiness report. Timeout and cache settings
also have safe ranges.

<code>python run_spoofzero.py --check</code> reports app, storage, model, and
configured external-service state without contacting services. It never prints
credentials, database paths, or private evidence. External connectivity and key
validity are therefore unknown until a user-authorized analysis performs a
lookup.
