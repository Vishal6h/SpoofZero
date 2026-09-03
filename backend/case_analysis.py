"""Batch adapter that reuses the unchanged single-email analysis pipeline."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from .case_store import MAX_CASE_EMAILS


MAX_BATCH_FILES = 25
MAX_EMAIL_BYTES = 10 * 1024 * 1024


def analyze_batch(files, case_id, store, analysis_fn=None):
    """Yield per-file outcomes; duplicates skip analysis and failures stay isolated.

    files is a sequence of (display filename, raw EML bytes) pairs. It may also
    contain lazy byte readers, so the UI need not copy the whole batch into RAM.
    Temporary payloads are always removed, including after parser failures.
    """
    if len(files) > MAX_BATCH_FILES:
        raise ValueError(f"Analyze at most {MAX_BATCH_FILES} emails per batch")
    existing_count = len(store.list_analyses(case_id))
    if analysis_fn is None:
        from .analyze import analyze_email
        analysis_fn = analyze_email

    for filename, content in files:
        try:
            content = content() if callable(content) else content
            if not isinstance(content, bytes) or not content:
                raise ValueError("The EML file is empty or unreadable")
            if len(content) > MAX_EMAIL_BYTES:
                raise ValueError("Batch emails must be 10 MiB or smaller")
            digest = sha256(content).hexdigest()
            existing = store.get_analysis(case_id, digest)
            if existing:
                yield {"filename": filename, "status": "duplicate", "email_id": digest,
                       "analysis": existing["analysis"]}
                continue
            if existing_count >= MAX_CASE_EMAILS:
                raise ValueError(f"Each case supports up to {MAX_CASE_EMAILS} unique emails")

            with TemporaryDirectory(prefix="spoofzero-case-") as directory:
                # Uploaded filenames are labels, never filesystem paths.
                path = Path(directory) / "email.eml"
                path.write_bytes(content)
                analysis = deepcopy(analysis_fn(str(path)))
                analysis.setdefault("email", {})["sha256"] = digest
            inserted = store.add_analysis(case_id, filename, analysis)
            existing_count += int(inserted)
            if not inserted:
                analysis = store.get_analysis(case_id, digest)["analysis"]
            yield {"filename": filename, "status": "saved" if inserted else "duplicate",
                   "email_id": digest, "analysis": analysis}
        except Exception as error:
            yield {"filename": filename, "status": "error", "message": str(error)}
