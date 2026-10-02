# Validation

| File | What it is |
|---|---|
| [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md) | The report: what the tool claims, the test data and how little control there was over it, the results, the failures, the limitations. **Start here.** |
| `results.json` | Every figure in the report, and the run it came from: engine image, baseline-table hash, tier counts, intervals, the capture corpora with URLs and SHA-256 digests, and the pre-registered expectations. |
| `apk_samples.csv` | One row per sample per run: SHA-256, the tier the engine gave it, and the label. MalwareBazaar samples are identified by digest only. |

The report is **generated**, not written: `scripts/build_validation_report.py` renders it from
`results.json`, and a test requires the committed file to equal a regeneration, so no number in
it was edited by hand. `results.json` is itself derived by `scripts/extract_validation_data.py`
from run logs and corpus manifests; where the engine's own log carries a tally, the derived counts
must equal it or the script stops.

**Change control.** The report names the SHA-256 of the shipped APK baseline table and of the
network rate table. A test fails if either file changes without the data being re-derived, so
the report cannot quietly describe a previous version of the tool.

## Regenerating

```bash
# After re-measuring (needs the local corpora and logs):
python scripts/extract_validation_data.py --analysis ../apk_corpus/analysis \
       --mal ~/26_class/mal --benign ../apk_corpus/benign
python scripts/build_validation_report.py
python backend/manage.py test capture.tests_validation
```

## What this is, and is not

It is information about testing, supplied by the developer, in the form the UK Forensic Science
Regulator's validation guidance (FSR-G-218) asks a record to take. It is not a validation of
any laboratory's method, it has not been independently reviewed, and it sets no acceptance
criteria. The guidance puts the onus of validation on the unit that uses the method; this
is meant to give that unit something to start from.
