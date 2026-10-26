# Guardian Pro — Architecture

## Purpose

Guardian Pro is a local Windows desktop application. It performs a small set of
defensive checks, stores a sanitized audit history, compares consecutive audits,
and produces a deterministic action plan. It is not a security score, a
compliance certification, an EDR, or a vulnerability scanner.

The design separates three concerns:

| Layer | File | Responsibility |
|-------|------|----------------|
| UI and orchestration | `Guardian.py` | CustomTkinter views, audit/repair lifecycle, Windows checks, PDF |
| Workspace data | `guardian_workspace.py` | History, fleet, comparison, priorities, JSON schema, demo data |
| Tests | `test_guardian.py`, `test_guardian_workspace.py` | Regression and new data/UI coverage |

`guardian_workspace.py` does not import Tkinter and does not execute commands.
This keeps persistence, comparison, and validation testable without a GUI.

## UI structure

The main window has a fixed sidebar and a content area:

- **Resumen ejecutivo** (`overview`): last evaluation, counts, attention trend,
  priority findings, and changes from the previous audit.
- **Plan de acción** (`action`): deterministic plan cards with what was
  detected, why it matters, next step, verification, and repair availability.
- **Historial** (`history`): bounded local audit list and comparison detail.
- **Vista de equipos** (`fleet`): local latest state plus imported JSON reports,
  sorted by high findings, attention items, and recency.
- **Auditoría del sistema** (`audit`): live progress, legacy summary counters,
  and the detailed results console.

Legacy test/UI attributes such as `btn_audit`, `btn_repair`, `btn_report`,
`btn_new_audit`, `btn_select_folder`, `summary_labels`, `lbl_progress`,
`progress_bar`, and `txt_results` are preserved.

## Local storage

Default directory:

```text
%LOCALAPPDATA%\GuardianPro
```

Override for isolated runs and tests:

```text
GUARDIAN_PRO_DATA_DIR=<directory>
```

Files:

```text
history.json   # local audits, schema guardian.history
fleet.json     # imported reports, schema guardian.fleet
```

### Limits

| Limit | Value |
|-------|-------|
| Local audits | 100 |
| History file | 5 MB |
| Imported reports | 200 |
| Fleet file | 5 MB |
| One imported report file | 1 MB |
| Checks per audit | 100 |
| Check name | 200 characters |
| Recommendation | 500 characters |
| Device name | 100 characters |
| Operating system text | 200 characters |

### Atomic writes and corruption handling

- JSON is written to a temporary file in the same directory, flushed, `fsync`ed,
  and moved into place with `os.replace`.
- If a file is missing, an empty collection is returned.
- If a file is corrupt, oversized, has an unknown schema/version, or contains
  invalid records, the valid records are loaded where possible and a warning is
  reported.
- Before a new write replaces a problematic file, the original is copied to
  `history.corrupt-<timestamp>.json` or `fleet.corrupt-<timestamp>.json`.
- Storage failures are caught by the UI. A failed history write does not stop
  the audit result, the action plan, or PDF generation.

## Audit record

Local history records use `guardian.audit`:

```json
{
  "schema": "guardian.audit",
  "schema_version": 1,
  "audit_id": "audit_<hex>",
  "collected_at": "2026-10-26T10:00:00+00:00",
  "device": {
    "id": "dev_<hash>",
    "name": "HOSTNAME",
    "os": "Windows 11 Pro"
  },
  "summary": {
    "ok": 2,
    "finding": 1,
    "unverifiable": 1,
    "error": 0
  },
  "checks": [
    {
      "check_id": "firewall",
      "name": "Firewall de Windows",
      "status": "finding",
      "severity": "high",
      "recommendation": "Habilite el firewall..."
    }
  ],
  "comparison": {
    "previous_audit_id": "audit_...",
    "current_audit_id": "audit_...",
    "new": [],
    "persistent": [],
    "resolved": [],
    "unverifiable": [],
    "not_evaluated": [],
    "regressed": [],
    "summary": {
      "new": 0,
      "persistent": 1,
      "resolved": 1,
      "unverifiable": 0,
      "not_evaluated": 0,
      "regressed": 0
    }
  }
}
```

`comparison` is optional. It is present when a previous valid audit exists for
the same device.

### Device identity

On Windows, `MachineGuid` is read only as input to a SHA-256 hash. The original
value is never stored or exported. The stored ID is `dev_` plus a truncated
hash. If the registry value is unavailable, hostname, platform, and network node
are hashed instead.

## Public report schema

Exported and imported reports use `guardian.report`. The top-level and check
objects must contain exactly the documented keys; unknown fields are rejected.

```json
{
  "schema": "guardian.report",
  "schema_version": 1,
  "audit_id": "audit_...",
  "collected_at": "2026-10-26T10:00:00+00:00",
  "device": {
    "id": "dev_...",
    "name": "HOSTNAME",
    "os": "Windows 11 Pro"
  },
  "summary": {
    "ok": 2,
    "finding": 1,
    "unverifiable": 1,
    "error": 0
  },
  "checks": [
    {
      "check_id": "firewall",
      "name": "Firewall de Windows",
      "status": "finding",
      "severity": "high",
      "recommendation": "Habilite el firewall..."
    }
  ]
}
```

Validation rules:

- `schema` must be exactly `guardian.report`.
- `schema_version` must be exactly `1`.
- `audit_id` is 1–128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, `-`.
- `collected_at` must be ISO 8601 with an explicit timezone.
- Device `id` uses the same character set and is 1–128 characters.
- Device `name` is required; `os` may be empty.
- Status is one of `ok`, `finding`, `error`, `unverifiable`.
- Severity is one of `high`, `medium`, `low`, `info`.
- The check list has 1–100 entries.
- Summary counters are non-negative integers and must match the checks exactly.
- Duplicate `audit_id` values and duplicate `check_id` values are rejected.
- A report older than or equal to the latest known report for the same device is
  imported and classified as `older`; it does not replace the fleet latest.
- Imported reports are displayed as text only. No field is executed, used to
  build a command, or used to enable repairs.

The export conversion deliberately removes `comparison`, evidence, paths, and
file names. Check names, device names, operating-system text, and recommendations
are normalized; path-like text is redacted. Duplicate `check_id` values are
rejected so comparison and display remain unambiguous.

The current UI exports one sanitized report at a time. Importing several reports
builds the local fleet; a consolidated fleet export is not implemented yet.

## Comparison semantics

Checks are matched by `check_id` within the same device.

| Category | Rule |
|----------|------|
| New finding | Current status is `finding`; no previous check or previous status was `ok`. |
| Persistent | Current status is non-OK and the previous status was also non-OK. |
| Resolved | Previous status was non-OK and current status is exactly `ok`. |
| Unverifiable | Current status is `error` or `unverifiable`. |
| Not evaluated | A previous non-OK check is absent from the current audit. |
| Regressed | A previous `ok` check is now `finding`, `error`, or `unverifiable`. |

Important: an error, an unverifiable result, or a missing check is never counted
as resolved. A repair command that ran is not proof of correction. Only a later
audit with `ok` confirms resolution.

## Deterministic action plan

The plan is built from non-OK checks. Priority order is:

1. High-severity findings.
2. Errors and unverifiable checks (review required; not OK).
3. Medium-severity findings.
4. Low-severity findings.
5. Other findings.

Within the same group, severity, repair availability, and `check_id` provide a
stable tie-break. No random order and no arbitrary 0–100 score are used.

Each plan item contains:

- what was detected,
- why it matters,
- next step,
- verification method,
- whether a Guardian repair is available,
- whether manual intervention is required.

Repair availability is restricted to the current real audit and to supported
firewall/RDP findings. Defender is always manual. History, imported reports, and
demo data are always built with `allow_repair=False`.

## Demo mode

`generate_demo_audits()` creates four audits for three synthetic devices in
memory. It never writes to `history.json` or `fleet.json`. While demo mode is
active:

- a persistent `DEMO — DATOS FICTICIOS` banner is shown;
- the sidebar shows the demo label;
- audits, repairs, PDF generation, export, and import are disabled;
- the fleet, overview, history, and plan views use only demo records.

Exiting demo restores the real views without modifying real history.

## Failure behavior

- A failed audit worker finalizes the operation so another audit can start.
- A failed storage write is reported in the UI and log; the current in-memory
  audit remains available for PDF generation.
- A failed import file is reported individually; other valid files continue.
- Import runs in a background thread and updates the UI through a queue.
- A missing or invalid comparison is shown as unavailable, not as a resolution.
- PDF generation catches its own exceptions and reports them without crashing
  the application.

## Validation

```bash
python -m py_compile Guardian.py guardian_workspace.py test_guardian.py test_guardian_workspace.py
python -m unittest -v
python -m pip check
git diff --check
```

The suite does not execute real repairs or modify firewall, Defender, RDP, or
registry settings. Windows providers are mocked. Real VM validation remains a
separate manual step.

## Known limitations

- Local JSON is not encrypted.
- The JSON export is sanitized but still identifies the device by name and
  hashed ID.
- PDFs may contain paths, filenames, and technical evidence.
- Comparisons require stored or imported reports; there is no central server.
- The plan explains priorities but cannot prove that a control is secure.
- A residual time-of-check/time-of-use window remains in filesystem validation.
- Guardian does not certify compliance or guarantee security.
