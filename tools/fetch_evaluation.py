"""Download inert, deterministic public samples; never visit email links."""
import hashlib
import io
import json
import tarfile
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / ".evaluation-data"
LIMIT = 100
HAM_ARCHIVE_SHA256 = "f9fc56e1f68780f9afdc6d23a2e24c4584af988afc58bbfabae500e51f3a2f36"
PHISHING_COMMIT = "89e2bc05d159555389782f2fbe8d916588cd49cd"

def fetch(url, limit=8_000_000):
    request = urllib.request.Request(url, headers={"User-Agent": "SentryAI-evaluation"})
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Download too large")
    return data

def main():
    ROOT.mkdir(exist_ok=True)
    ham_dir = ROOT / "ham"
    phish_dir = ROOT / "phishing"
    ham_dir.mkdir(exist_ok=True)
    phish_dir.mkdir(exist_ok=True)
    ham_url = "https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2"
    archive = fetch(ham_url)
    if hashlib.sha256(archive).hexdigest() != HAM_ARCHIVE_SHA256:
        raise ValueError("Ham archive changed; review the evaluation source before proceeding")
    ham_manifest = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:bz2") as corpus:
        members = [m for m in corpus.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1][0:1].isdigit()]
        members.sort(key=lambda m: hashlib.sha256(m.name.encode()).hexdigest())
        for member in members[:LIMIT]:
            if member.size > 2_000_000:
                raise ValueError("Email too large")
            data = corpus.extractfile(member).read()
            digest = hashlib.sha256(data).hexdigest()
            (ham_dir / (digest + ".eml")).write_bytes(data)
            ham_manifest.append({"source_path": member.name, "sha256": digest})
    print("Downloaded benign sample", len(ham_manifest), flush=True)
    commit = PHISHING_COMMIT
    tree = json.loads(fetch("https://api.github.com/repos/rf-peixoto/phishing_pot/git/trees/" + commit + "?recursive=1"))
    paths = [item["path"] for item in tree["tree"] if item["type"] == "blob" and item["path"].startswith("email/") and item["path"].endswith(".eml")]
    paths.sort(key=lambda p: hashlib.sha256(p.encode()).hexdigest())
    def download(path):
        url = "https://raw.githubusercontent.com/rf-peixoto/phishing_pot/" + commit + "/" + urllib.parse.quote(path)
        data = fetch(url, 2_000_000)
        digest = hashlib.sha256(data).hexdigest()
        (phish_dir / (digest + ".eml")).write_bytes(data)
        return {"source_path": path, "sha256": digest}
    with ThreadPoolExecutor(max_workers=6) as pool:
        phish_manifest = list(pool.map(download, paths[:LIMIT]))
    manifest = {"selection": "First 100 paths ordered by SHA-256 of source path", "ham_source": ham_url,
                "ham_archive_sha256": hashlib.sha256(archive).hexdigest(), "phishing_source": "https://github.com/rf-peixoto/phishing_pot",
                "phishing_commit": commit, "ham": ham_manifest, "phishing": phish_manifest}
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("Downloaded phishing sample", len(phish_manifest), flush=True)

if __name__ == "__main__":
    main()
