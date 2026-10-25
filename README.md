# Guardian Pro — Windows Security Check

## Overview
Guardian Pro is a **local Windows desktop application** for basic defensive security checks. It is aimed at individuals and small businesses without dedicated security staff who want a readable view of a few common Windows settings.

> **Important:** Guardian Pro is an educational, defensive-check prototype. It does **not** replace a professional security assessment, antivirus/EDR, vulnerability scanning, or compliance review. Results are advisory only.

## Features Implemented

| Check | What it verifies | Remediation |
|-------|------------------|-------------|
| **Windows Firewall** | Domain, Private, and Public profiles individually | Enable all profiles (requires Administrator) |
| **Microsoft Defender** | Real-time protection status | Enable real-time monitoring (requires Administrator) |
| **Remote Desktop (RDP)** | Registry value `fDenyTSConnections`, local TCP port 3389, and built-in RDP firewall rules identified by the language-independent group `@FirewallAPI.dll,-28752` | Disable RDP via registry + disable built-in RDP firewall rules (requires Administrator, **disrupts remote access**) |
| **Sensitive Filenames** | Walks the selected folder and matches keywords in **filenames only** (extensions: `.txt`, `.pdf`, `.env`, `.docx`, `.xlsx`, `.csv`, `.json`, `.xml`, `.ini`, `.config`) | Review manually — **no automated fix** |

The application reports four result states: **OK**, **Finding**, **Not Verifiable**, and **Error**. The UI color is selected from the result state first; severity does not turn an error or an unverifiable result into a green OK.

## Requirements
- Windows 10/11 with PowerShell 5.1+
- Python 3.10+
- Dependencies from `requirements.txt`:
  - `customtkinter` — desktop UI
  - `fpdf2` — PDF report generation

## Installation & Execution
```bash
git clone https://github.com/porsellaj/guardian-pro-security-auditor
cd guardian-pro-security-auditor
pip install -r requirements.txt
python Guardian.py
```

Run **as Administrator** for:
- Firewall, Defender, or RDP repairs.
- Broader filename scanning. Protected directories can still be inaccessible or intentionally excluded; access/traversal errors are reported rather than hidden.

## How It Works
1. **Select a folder** for filename analysis (default: the current user profile).
2. **Start an audit** — four checks run in a background thread and the UI remains responsive.
3. **Review results** — each check shows a status, evidence, and a recommendation.
4. **Repair (optional)** — automated fixes are offered only for supported findings. Each action is confirmed separately and shows the change, exact command, possible adverse effects, and whether Administrator rights are required.
5. **Generate a PDF** — the report includes the audit scope, check results, repair history, and sensitive filenames found.

### Audit state and report lifecycle
- Starting a new audit resets check results, summary counters, sensitive filenames, and repair history.
- Opening the repair dialog does **not** erase repair history already recorded for the current audit. Only the newly confirmed batch is executed.
- Results from the current audit remain available for the PDF until the user starts a new audit.
- The “New audit” action is blocked and disabled while an audit or repair is active.
- A worker exception finalizes the operation so another audit can be started afterwards.

## Check Details & Limitations

### Firewall
- Queries `Get-NetFirewallProfile` for Domain, Private, and Public.
- Verification requires PowerShell exit code `0`, valid JSON, all three profiles present, and each one explicitly enabled.
- **Limitation:** Does not inspect individual firewall rules or application exceptions.

### Microsoft Defender
- Queries `Get-MpComputerStatus.RealTimeProtectionEnabled`.
- Verification accepts only an explicit `True`.
- **Limitation:** Does not check cloud-delivered protection, tamper protection, signatures, or third-party antivirus presence.

### RDP
- Reads registry `HKLM:\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`.
- Tests TCP connection to `127.0.0.1:3389` as an additional local signal only.
- Queries RDP firewall rules by the language-independent group `@FirewallAPI.dll,-28752`, not by a localized display name.
- Parses the PowerShell `Enabled` values explicitly: `1`/`True` = enabled; `0`/`False` = disabled; `2` = not configured (not enabled). Unexpected values are treated as unverifiable/error.
- RDP is considered confirmed enabled only when the registry value is `0`. An open local port alone does **not** offer the RDP repair.
- RDP verification requires registry `fDenyTSConnections=1` and a successful RDP firewall-rule query with no enabled rules. Registry and firewall evidence are reported separately.
- **Limitation:** A local port 3389 check does not prove external exposure. No external scanning or RDP protocol negotiation is performed.

### Sensitive Filenames
- Walks the selected folder with `os.walk(..., onerror=..., followlinks=False)`.
- Excludes directories such as `AppData`, `Windows`, `Program Files`, `ProgramData`, `node_modules`, `.git`, `.vs`, `__pycache__`, `temp`, and `tmp` by modifying `dirs[:]` in place.
- Matches keywords in **filenames only**; file contents are not opened.
- Uses `os.stat(..., follow_symlinks=False)` on files only to detect metadata/access errors. It does not modify, move, open, or delete files.
- Reports unreadable roots, traversal errors, and file access errors. If there are no matches but some elements could not be examined, the result is **Not Verifiable**, not a confirmed absence.
- **Limitations:** False positives are expected (for example, `password_requirements.txt`). Excluded directories are intentionally not examined. The number of descendants inside an unreadable directory is not known, so only the number of failed directories/files is reported. `os.stat` on every file adds overhead on very large trees.

## Repair Actions
- Each repair shows its name, description, exact PowerShell command, possible adverse effects, and Administrator requirement.
- **Explicit per-action confirmation is required.** Rejecting one action does not prevent confirming another.
- Administrator rights are checked with the current Windows token. Protected actions are not executed without them, no elevation is attempted, and the action is recorded as **not executed due to permissions**, not as a Guardian failure.
- Repair type is selected by an explicit action identifier (`firewall_enable_all`, `defender_enable_rtp`, `rdp_disable`), not by searching command text.
- A command that ran but could not be verified is reported as **executed, not verified** or **executed, verification error**; it is never reported as verified.
- Repair history, including skipped and permission-blocked actions, is included in the PDF report.
- **RDP disable warning:** May interrupt active remote sessions and block legitimate remote access.

## PDF Report Contains
- Application name, generation time, and audit timestamp.
- The selected folder as the analysis scope, with a note that access/traversal errors mean the folder was not fully covered.
- Summary counts (OK / Findings / Not Verifiable / Errors).
- Per-check detail: name, status, evidence, and recommendation.
- Repair log: action, command, output, error, verification evidence, and result (verified, executed but not verified, verification error, failed, skipped, or not executed due to permissions).
- Sensitive filenames (limited to 50 entries).
- A privacy notice and a clear disclaimer that this is not a professional assessment.

> **Privacy:** PDF reports can contain local paths, filenames, or other user-identifying information. Review a report before sharing it.

## Testing & Validation

### Automated tests
The regression suite uses the standard library `unittest` and mocks. It does not execute repairs or modify Windows security settings.

```bash
python -m unittest -v
```

The suite covers:
- Result-state color mapping, including `unverifiable`/`error` with `severity="info"` or `"high"`.
- Accessible filename trees, matches, exclusions, inaccessible roots, `os.walk(onerror=...)` errors, file access errors, and partial results.
- Audit finalization, state reset between consecutive audits, failed-audit recovery, active-operation guards, and repair-history preservation.
- Explicit repair dispatch by action type, strict firewall/Defender/RDP verification, RDP repair only from registry-confirmed state, Administrator re-checks, skipped actions, and failed actions.
- PDF generation with scope, all result states, repair states, privacy notice, and valid PDF header/content checks.

### Additional checks performed
| Check | Result |
|-------|--------|
| `python -m py_compile Guardian.py` | Pass |
| `python -m unittest -v` | Pass — 44 tests |
| Real read-only audit on this Windows machine | Pass — Firewall OK, Defender OK, RDP OK, filename scan OK; no settings changed |
| PDF test generation | Pass — valid `%PDF-` file; scope, statuses, repair history, and privacy text checked |
| `python -m pip check` | Pass — no broken requirements |
| `git diff --check` | Pass — only LF-to-CRLF warnings |

> No firewall, Microsoft Defender, registry, or RDP setting was changed during validation. Repair behavior was exercised with mocked PowerShell responses only.

### Manual validation still required on Windows
- Real repair execution with Administrator rights, followed by real post-repair verification.
- Real elevated and non-elevated GUI behavior.
- UI responsiveness during very large file scans.
- Final visual review of the generated PDF in a PDF viewer.

## Known Limitations
- Real repair verification depends on the same PowerShell/CIM providers used by the checks and has not been exercised against a real changed system state.
- PowerShell/CIM provider availability and permissions can vary between Windows editions and managed environments.
- The filename scan examines names, not content; it cannot confirm whether a file actually contains sensitive data.
- Excluded system/development directories are not scanned, and inaccessible directories cannot be enumerated internally.
- RDP checks are local only; they do not test external exposure or RDP negotiation.
- Large trees may take time because each filename is also checked with `os.stat` to detect access errors.
- The PDF layout has not been reviewed visually in every PDF viewer.

## Project Structure
```
guardian-pro-security-auditor/
├── Guardian.py       # Main application (UI + checks + PDF)
├── test_guardian.py  # unittest regression suite
├── README.md         # This file
├── requirements.txt  # Python dependencies
└── .gitignore        # Local artifacts and generated reports
```

## License
MIT — see LICENSE if present. Otherwise, free for educational and personal use.

## Author
Joaquín Porsella
