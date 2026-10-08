# Public email evaluation — 8 October 2026

This offline diagnostic measures the classifier on 100 benign and 100
source-labelled phishing samples. The classifier still misses many samples;
it is not ready for unattended mail filtering. Security hardening improves
trust and failure handling; it does not establish production detection accuracy.

## Sources and reproducibility

- Benign: [Apache SpamAssassin easy-ham corpus](https://spamassassin.apache.org/old/publiccorpus/), archive `20021010_easy_ham.tar.bz2`.
- Phishing-labelled: [Phishing Pot](https://github.com/rf-peixoto/phishing_pot), commit `89e2bc05d159555389782f2fbe8d916588cd49cd`.
- Baseline: SentryAI commit `1de2731807058ae897bc5c0937b4bde6dbca963b`.

For each source, select the first 100 source paths ordered by SHA-256 of the
path. Selection is fixed before scoring. The [manifest](evaluation-manifest.json)
records source paths and content hashes; [results](evaluation-results.json)
record predictions without email contents. Raw samples live only under the
ignored `.evaluation-data/` directory and are not committed.

The stdlib email parser decodes MIME text and hashes attachment bytes. It never
opens an email URL, executes an attachment, or renders HTML. Both runs use the
offline demo provider and `trust_missing_auth=True`. No SPF/DKIM/DMARC results
are considered verified. This isolates content/IOC heuristics without making
missing historic auth a blanket +50 signal. Source labels are not used as
inputs to the detector. No thresholds were fitted to this sample.

## Results

| Actual label | Version | BENIGN | SUSPICIOUS | PHISHING | ERROR |
|---|---|---:|---:|---:|---:|
| Benign (100) | Baseline | 69 | 29 | 2 | 0 |
| Benign (100) | Hardened | 72 | 28 | 0 | 0 |
| Phishing-labelled (100) | Baseline | 31 | 51 | 18 | 0 |
| Phishing-labelled (100) | Hardened | 32 | 53 | 15 | 0 |

| Metric | Baseline | Hardened |
|---|---:|---:|
| PHISHING recall | 18% | 15% |
| PHISHING precision | 90% | 100% |
| Benign falsely labelled PHISHING | 2% | 0% |
| Phishing-labelled marked SUSPICIOUS or PHISHING | 69% | 68% |
| Benign marked SUSPICIOUS or PHISHING | 31% | 28% |
| Phishing-labelled marked BENIGN | 31% | 32% |
| Human review recommended | 42/200 | 200/200 |

Precision counts only `PHISHING` predictions. Recall includes every
phishing-labelled sample in its denominator, including errors if present.
Suspicious cases are shown separately. Review flags are not counted as
successful phishing detections. Hardened results require review for every
sample because authentication provenance is absent; low-confidence benign
results do not recommend delivery.

The content refinements remove two benign PHISHING predictions, but strict
phishing recall falls by three cases. This tradeoff is visible in the report;
100% precision here does not imply zero false positives on new mail.

## Limitations and next accuracy work

This small, deterministic sample mixes very old benign mail with newer
honeypot captures. It is not representative of a user's inbox. Phishing Pot's
source labels can include marketing/spam messages; they have not been
independently adjudicated here. No live reputation is queried, and demo data
is not current threat intelligence. English keyword rules, HTML obfuscation,
attachment-only attacks and a limited trusted-domain list remain gaps.

A production accuracy gate needs a larger, independently labelled corpus,
matching time periods and languages, verified receiving-system metadata,
separate calibration and held-out sets, and an explicit tolerance for false
positives. The measured miss rate remains a limitation rather than a solved bug.

## Run again

```powershell
python tools/fetch_evaluation.py
python tools/evaluate.py --ham .evaluation-data/ham --phishing .evaluation-data/phishing --output .evaluation-data/current-results.json
```

The fetch script pins the phishing source commit and selection rule. To compare
the baseline, export that commit's `sentryai/` directory into a separate local
folder and pass its parent with `--package-root`. The evaluator accepts local
labelled `.eml` directories, so a future approved corpus can replace these samples.
