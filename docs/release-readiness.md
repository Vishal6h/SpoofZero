# SpoofZero v1.0.0-rc1 release readiness

This is a release candidate. No Git tag, remote push, image publication, or live
deployment is part of this milestone.

## Verification checklist

- [x] Tests: 417 offline tests pass with zero failures, errors, or skips.
- [x] Secrets: environment files, keys, and generated/private evidence remain ignored.
- [x] Git cleanliness: no files are staged; no remote or release tag was added.
- [x] Model state: protected legacy bytes match and all nine candidates remain blocked.
- [x] Fusion state: validated_evidence_fusion_v2 and 20/40/60/80 thresholds are unchanged.
- [x] Demo mode: repository evidence runs with every live service disabled.
- [x] Installation: Python and pinned-dependency setup is documented.
- [x] Startup: cross-directory readiness and real local Streamlit health checks pass.
- [x] Reports: JSON/HTML generation, disclosures, and SHA-256 integrity verification pass.
- [x] Case migration/history: existing migration tests pass and snapshots remain immutable.
- [x] Privacy: raw bodies/payloads stay out of cases; privacy-safe default is configurable.
- [x] Security: disabled/failed intelligence remains UNKNOWN and local limits remain enforced.
- [x] Deployment requirements: HTTPS, auth, limits, isolation, storage, and operations are documented.
- [x] Known limitations: AI, authentication, correlation, geolocation, storage, and public hosting are disclosed.
- [x] Static gates: compileall and git diff --check pass.
- [x] Protected scores: fresh v2 demo is 75 with 0 AI points; historical v1 remains 69.

## Assessment

| Use | Status | Conditions |
| --- | --- | --- |
| Local demo | **YES** | Use demo mode; repository samples only; no live services |
| SIH presentation | **YES** | Present limitations and keep the system local/offline |
| Controlled private deployment | **CONDITIONAL** | Trusted users, HTTPS/auth proxy, protected storage, retention policy, provider review |
| Unrestricted public deployment | **NO** | Missing native auth/authorization, tenant isolation, encrypted storage, production database, and abuse controls |

These statuses describe operational readiness, not scientific validation of the
AI classifier. The active compatibility model remains experimental and research
candidates remain blocked by existing deployment gates.
