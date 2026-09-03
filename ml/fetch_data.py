"""Fetch checksum-pinned public CSV text only; never follow links in messages."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent


def fetch_source(source, directory):
    name = source["file"]
    if Path(name).name != name or not name.endswith(".csv"):
        raise ValueError("Only named CSV text assets are permitted")
    if source["license"] != "CC-BY-4.0":
        raise ValueError("Source license requires explicit recipe review")
    url = source["url"]
    if not url.startswith("https://zenodo.org/api/records/8339691/files/") or not url.endswith("/content"):
        raise ValueError("Download is outside the reviewed source record")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    algorithm, expected = source["checksum"].split(":", 1)
    def verify(path):
        return hashlib.new(algorithm, path.read_bytes()).hexdigest() == expected
    if target.exists():
        if not verify(target):
            raise ValueError("Existing download checksum mismatch")
        return name
    temporary = directory / (name + ".part")
    try:
        with urllib.request.urlopen(url, timeout=45) as response, temporary.open("wb") as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 50 * 1024 * 1024:
                    raise ValueError("CSV exceeds reviewed download size limit")
                output.write(chunk)
        if not verify(temporary):
            raise ValueError("Downloaded CSV checksum mismatch")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, default=ROOT / "data/sources.json")
    parser.add_argument("--output", type=Path, default=ROOT / "data/raw")
    args = parser.parse_args()
    recipe = json.loads(args.recipe.read_text())
    with ThreadPoolExecutor(max_workers=4) as workers:
        for name in workers.map(lambda source: fetch_source(source, args.output), recipe["sources"]):
            print("Verified public CSV:", name, flush=True)


if __name__ == "__main__":
    main()
