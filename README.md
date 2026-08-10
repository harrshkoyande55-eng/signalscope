# SignalScope

Privacy-first incident intelligence in Python. SignalScope parses logs, fingerprints repeated failures, scores anomalies, ranks service risk, and saves analysis runs in SQLite.

## Run

Requires Python 3.10+; no third-party packages.

```bash
python app.py
```

Open http://localhost:8000 and click **Load demo incident**.

## Test

```bash
python -m unittest -v
```

Accepted format:

```text
2026-08-10T14:02:14Z ERROR payments - gateway timeout after 5000ms
```

## Interview talking points

SignalScope addresses alert fatigue without uploading sensitive logs. Its normalizer removes changing IDs, paths, addresses, and measurements before hashing messages, allowing related failures to form one cluster. Anomaly scores combine severity with logarithmic recurrence so repetition matters without letting low-risk noise dominate.

The analysis engine, HTTP API, persistence layer, and responsive UI are separated cleanly. The server validates timestamps and limits request size; the engine is unit-tested. Natural next steps include streaming ingestion, rolling-window baselines, OpenTelemetry support, authentication, and container deployment.
