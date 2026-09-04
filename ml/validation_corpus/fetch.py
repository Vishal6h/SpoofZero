"""Download only explicitly reviewed, pinned CSV/JSON text assets."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
import requests
from ml.data_pipeline import ROOT

RECIPE = ROOT / "data/sources_real_world_v1.json"
RAW = ROOT / "data/raw/real_world_v1"

def fetch(destination=RAW):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    recipe = json.loads(RECIPE.read_text())
    for asset in recipe["assets"]:
        if asset["filename"] not in {"spaphish.csv", "spaphish_schema.json", "smishx.csv"}:
            raise ValueError("Unreviewed asset")
        url = asset["url"]
        if urlparse(url).scheme != "https" or urlparse(url).hostname not in {"data.mendeley.com", "raw.githubusercontent.com"}:
            raise ValueError("Unreviewed publisher")
        path = destination / asset["filename"]
        if path.exists():
            content = path.read_bytes()
        else:
            # Never request archives, MIME messages, attachments, scripts, or URLs in emails.
            with requests.get(url, stream=True, timeout=60) as response:
                response.raise_for_status()
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > asset["bytes"]:
                        raise ValueError("Unexpected asset size")
                    chunks.append(chunk)
                content = b"".join(chunks)
        if len(content) != asset["bytes"] or hashlib.sha256(content).hexdigest() != asset["sha256"]:
            raise ValueError("Pinned data checksum mismatch")
        content.decode("utf-8-sig")
        if not path.exists():
            path.write_bytes(content)
        print(asset["filename"], "checksum verified", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=RAW)
    fetch(parser.parse_args().destination)
