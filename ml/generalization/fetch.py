"""Fetch only three reviewed version-pinned public CSVs into ignored storage."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

from ml.data_pipeline import ROOT

REVIEWED = {
    "TREC-06.csv": ("https://ndownloader.figshare.com/files/45117808",
                    "CC-BY-4.0", "8ca6b1249f30f0a74790b8a34d4dbe248d526cfb0b13227b41970a1ebd638be5", 45000000),
    "synthetic_emails.csv": ("https://www.kaggle.com/api/v1/datasets/download/yoadjei/adversarial-bec-email-dataset/synthetic_emails.csv?datasetVersionNumber=2",
                    "CC-BY-SA-4.0", "c6151b4fca463a48f5141303a911f7fb177af2c7b6314344fd52498603dd932e", 4000000),
    "phishing_legit_dataset_KD_10000.csv": ("https://www.kaggle.com/api/v1/datasets/download/kuladeep19/phishing-and-legitimate-emails-dataset/phishing_legit_dataset_KD_10000.csv?datasetVersionNumber=1",
                    "CC-BY-SA-4.0", "fb65d38e33e9fe070cc842abf3a6f7ed679da5ae0fd823cec31db46ede5f1aa7", 4000000),
}


def csv_bytes(data, name, limit):
    if len(data) > limit:
        raise ValueError("Download exceeds the reviewed size bound")
    if data.startswith(b"PK"):
        # Some publishers wrap a single CSV. Never extract paths or other assets.
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.namelist() != [name] or archive.getinfo(name).file_size > limit:
                raise ValueError("Expected exactly the reviewed bounded CSV")
            data = archive.read(name)
    if b"\0" in data:
        raise ValueError("Binary content is not an admitted email-text CSV")
    data.decode("utf-8-sig")
    return data


def fetch_source(source, directory):
    name = source["file"]
    if name not in REVIEWED:
        raise ValueError("Source is outside the reviewed v2 asset allowlist")
    url, license_name, sha256, limit = REVIEWED[name]
    if (source["url"], source["license"], source["sha256"]) != (url, license_name, sha256):
        raise ValueError("Source differs from the reviewed version/license/checksum")
    target = Path(directory) / name
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != sha256:
            raise ValueError("Existing public CSV checksum mismatch")
        return target
    request = urllib.request.Request(url, headers={"User-Agent": "SpoofZero-public-text-research"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = csv_bytes(response.read(limit + 1), name, limit)
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("Public CSV checksum mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as handle:
        handle.write(data)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, default=ROOT / "data/sources_v2.json")
    parser.add_argument("--output", type=Path, default=ROOT / "data/raw/v2")
    args = parser.parse_args()
    for source in json.loads(args.recipe.read_text())["additional_sources"]:
        print("Verified:", fetch_source(source, args.output).name, flush=True)


if __name__ == "__main__":
    main()
