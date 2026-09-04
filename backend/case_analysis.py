"""Batch adapter that reuses the unchanged single-email analysis pipeline."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from .case_store import MAX_CASE_EMAILS
from .input_safety import DEFAULT_EMAIL_LIMITS, EmailInputError, safe_evidence_filename
from .observability import log_event


MAX_BATCH_FILES = 25
MAX_EMAIL_BYTES = DEFAULT_EMAIL_LIMITS.max_eml_bytes


def analyze_batch(files, case_id, store, analysis_fn=None, *,
                  allow_reanalysis=False, privacy_safe=False):
    """Yield per-file outcomes while isolating failures and removing payload files.

    By default an existing raw EML hash skips analysis and returns its latest
    snapshot. allow_reanalysis=True is an explicit request to run the forensic
    pipeline again and append another immutable version.
    """
    if len(files) > MAX_BATCH_FILES:
        raise ValueError(f"Analyze at most {MAX_BATCH_FILES} emails per batch")
    existing_count = len(store.list_analyses(case_id))
    if analysis_fn is None:
        from .analyze import analyze_email
        analysis_fn = analyze_email

    seen_batch = set()
    for filename, content in files:
        filename = safe_evidence_filename(filename or "email.eml")
        try:
            content = content() if callable(content) else content
            if not isinstance(content, bytes) or not content:
                raise ValueError("The EML file is empty or unreadable")
            if len(content) > MAX_EMAIL_BYTES:
                raise ValueError("Batch emails must be 10 MiB or smaller")
            digest = sha256(content).hexdigest()
            existing = store.get_analysis(case_id, digest)
            # Even explicit reanalysis runs at most once for identical payload
            # bytes within one batch operation.
            if digest in seen_batch or (existing and not allow_reanalysis):
                yield {
                    "filename": filename, "status": "duplicate", "email_id": digest,
                    "analysis_id": existing["analysis_id"] if existing else None,
                    "analysis": existing["analysis"] if existing else None,
                }
                continue
            if not existing and existing_count >= MAX_CASE_EMAILS:
                raise ValueError(f"Each case supports up to {MAX_CASE_EMAILS} unique emails")
            seen_batch.add(digest)

            with TemporaryDirectory(prefix="spoofzero-case-") as directory:
                path = Path(directory) / "email.eml"
                path.write_bytes(content)
                analysis = deepcopy(analysis_fn(str(path)))
                analysis.setdefault("email", {})["sha256"] = digest
            inserted = store.add_analysis(
                case_id, filename, analysis, allow_reanalysis=bool(existing),
                privacy_safe=privacy_safe,
            )
            if not inserted:
                saved = store.get_analysis(case_id, digest)
                analysis = saved["analysis"]
            else:
                saved = store.get_analysis(case_id, digest)
                existing_count += int(existing is None)
            yield {
                "filename": filename,
                "status": "reanalyzed" if existing and inserted else "saved" if inserted else "duplicate",
                "email_id": digest,
                "analysis_id": saved["analysis_id"] if saved else None,
                "analysis": analysis,
            }
        except EmailInputError as error:
            yield {"filename": filename, "status": "error", "message": str(error)}
        except Exception:
            log_event("analysis_failure", analyzer="batch", case_id=case_id,
                      service_status="ERROR")
            yield {
                "filename": filename, "status": "error",
                "message": "Analysis could not be completed safely for this file.",
            }
