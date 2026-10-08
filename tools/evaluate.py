"""Offline evaluation of labelled .eml directories; no email links fetched."""
import argparse
from collections import Counter
from email import policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import sys


def parse_message(path):
    data = path.read_bytes()
    if len(data) > 2_000_000:
        raise ValueError("Email exceeds evaluation size limit")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    plain, html, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_content_disposition() == "attachment" or part.get_filename():
            attachments.append({"filename": part.get_filename(), "sha256": hashlib.sha256(payload).hexdigest(), "mime_type": part.get_content_type()})
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            text = payload.decode(part.get_content_charset() or "utf-8", "replace")
        except LookupError:
            text = payload.decode("utf-8", "replace")
        (html if part.get_content_type() == "text/html" else plain).append(text)
    # Corpus headers have no trusted verifier provenance. Never parse auth.
    return {"email_id": hashlib.sha256(data).hexdigest(),
            "headers": {"from": str(msg.get("From", "")), "reply_to": str(msg.get("Reply-To", "")), "subject": str(msg.get("Subject", ""))},
            "body_text": "\n".join(plain) or None, "body_html": "\n".join(html) or None, "attachments": attachments}


def summarise(rows):
    matrix = {label: dict(Counter(row["verdict"] for row in rows if row["label"] == label)) for label in ("benign", "phishing")}
    counts = Counter(row["label"] for row in rows)
    tp = matrix["phishing"].get("PHISHING", 0)
    fp = matrix["benign"].get("PHISHING", 0)
    detected = tp + matrix["phishing"].get("SUSPICIOUS", 0)
    return {"counts": dict(counts), "matrix": matrix,
            "phishing_recall": tp / counts["phishing"] if counts["phishing"] else None,
            "phishing_precision": tp / (tp + fp) if tp + fp else None,
            "benign_false_positive_rate": fp / counts["benign"] if counts["benign"] else None,
            "phishing_suspicious_or_phishing_rate": detected / counts["phishing"] if counts["phishing"] else None,
            "errors": sum(row["verdict"] == "ERROR" for row in rows),
            "review_recommended": sum(row.get("review", False) for row in rows)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ham", type=Path, required=True)
    parser.add_argument("--phishing", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 1000:
        parser.error("limit must be 1..1000")
    sys.path.insert(0, str(args.package_root.resolve()))
    from sentryai.pipeline import analyze
    rows = []
    for label, folder in (("benign", args.ham), ("phishing", args.phishing)):
        paths = sorted(folder.glob("*.eml"))[:args.limit]
        if not paths:
            parser.error(f"No .eml files in {folder}")
        for path in paths:
            try:
                email = parse_message(path)
                # Neutral missing auth isolates content detection; evidence
                # remains missing and review requirements are counted separately.
                result = analyze(email, trust_missing_auth=True)
                rows.append({"id": email["email_id"], "label": label, "verdict": result["verdict"], "risk_score": result["risk_score"], "confidence": result["confidence"], "review": result["human_review_recommended"]})
            except Exception as exc:
                rows.append({"id": path.stem, "label": label, "verdict": "ERROR", "error_type": type(exc).__name__})
    result = {"mode": "offline demo reputation; missing authentication neutral; no trusted auth claims", "summary": summarise(rows), "results": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
    return 0 if not result["summary"]["errors"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
