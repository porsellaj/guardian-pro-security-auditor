# Guardian Pro — Windows Security Check

## Overview
Guardian Pro is a **local Windows desktop application** for basic defensive security checks. It is aimed at individuals and small businesses without dedicated security staff who want a readable view of a few common Windows settings.

> **Important:** Guardian Pro is an educational, defensive-check prototype. It does **not** replace a professional security assessment, antivirus/EDR, vulnerability scanning, or compliance review. Results are advisory only.

## Features Implemented

| Check | What it verifies | Remediation |
|-------|------------------|-------------|
| **Windows Firewall** | Domain, Private, and Public profiles individually | Enable all profiles (requires Administrator) |
| **Microsoft Defender** | Real-time protection status, plus Tamper Protection/antivirus/mode diagnostics when available | **Manual guidance only:** Guardian does not change real-time protection. Activate it in Windows Security, then run a new audit to verify the state. |
| **Remote Desktop (RDP)** | Registry value `fDenyTSConnections`, local TCP port 3389, and built-in RDP firewall rules identified by the language-independent group `@FirewallAPI.dll,-28752` | Disable RDP via registry + disable built-in RDP firewall rules (requires Administrator, **disrupts remote access**) |
| **Sensitive Filenames** | Resolves the selected folder to its real canonical path, rejects protected system roots and their real descendants before traversal, then walks the authorized tree and matches keywords in **filenames only** (extensions: `.txt`, `.pdf`, `.env`, `.docx`, `.xlsx`, `.csv`, `.json`, `.xml`, `.ini`, `.config`). Symbolic links, junctions, and reparse-point directories are excluded. | Review manually — **no automated fix** |

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
- Firewall and RDP repairs.
- Broader filename scanning. Protected directories can still be inaccessible or intentionally excluded; access/traversal errors are reported rather than hidden.

## How It Works
1. **Select a folder** for filename analysis (default: the current user profile). Guardian resolves the selected path with `os.path.realpath(..., strict=True)` and rejects protected system roots, their real descendants, complete drive roots, UNC share roots, and links that resolve into a protected location. The canonical path becomes the authorized scan scope.
2. **Start an audit** — four checks run in a background thread and the UI remains responsive.
3. **Review results** — each check shows a status, evidence, and a recommendation.
4. **Repair (optional)** — automated fixes are offered only for supported firewall and RDP findings. Microsoft Defender is detection-only: when real-time protection is off, Guardian shows a manual Windows Security guide instead of executing a command. Each automated action is confirmed separately and shows the change, exact command, possible adverse effects, and whether Administrator rights are required.
5. **Generate a PDF** — the report includes the audit scope, check results, repair history, sensitive filenames found, and the manual Defender activation guide when applicable.

### Audit state and report lifecycle
- Starting a completely new audit resets check results, summary counters, sensitive filenames, and repair history.
- Opening the repair dialog does **not** erase repair history already recorded for the current audit. Only the newly confirmed batch is executed.
- Before a confirmed repair batch runs, Guardian keeps an independent copy of the results that produced the findings.
- The automatic re-audit after repairs preserves that initial state and the action history. It is treated as a post-repair verification, not as an unrelated new audit.
- If the user starts a new audit instead of continuing the repair cycle, the previous correction context is discarded so old actions do not accumulate in future reports.
- The “New audit” action is blocked and disabled while an audit or repair is active.
- A worker exception finalizes the operation so another audit can be started afterwards.

## Check Details & Limitations

### Firewall
- Queries `Get-NetFirewallProfile` for Domain, Private, and Public.
- Verification requires PowerShell exit code `0`, valid JSON, all three profiles present, and each one explicitly enabled.
- **Limitation:** Does not inspect individual firewall rules or application exceptions.

### Microsoft Defender
- Queries `Get-MpComputerStatus` for the effective state and, when available, `Get-MpPreference` for the read-only `DisableRealtimeMonitoring` diagnostic.
- Reports `RealTimeProtectionEnabled`, `IsTamperProtected`, `AntivirusEnabled`, and `AMRunningMode` as diagnostics.
- **Guardian does not modify real-time protection.** There is no automatic Defender repair, no `Set-MpPreference` command, no registry workaround, and no attempt to disable Tamper Protection or override administrative policy.
- If real-time protection is disabled, the check remains a **Finding**. The UI and PDF explain that manual intervention is required and provide six numbered steps: Start → Windows Security → Virus & threat protection → Manage settings → Real-time protection → turn it on, then return to Guardian and run a new audit.
- The guide also notes that a disabled, locked, or self-reverting switch may be controlled by Tamper Protection, an administrative policy, or another antivirus configuration. Guardian reports these as possibilities without asserting an unproven cause.
- Verification is automated only through a new audit. If the user activates Defender manually and the new audit finds it active, Guardian reports the current state and does not claim that it performed the activation.
- PowerShell errors and timeouts are reported as **Error** or **Not Verifiable**, never as a confirmed disabled finding or a false OK.
- **Limitations:** Cloud-delivered protection, signatures, and full Defender health are not assessed. Manual activation has not been performed by the automated test suite; it requires validation on a real Windows VM.

### RDP
- Reads registry `HKLM:\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`.
- Tests TCP connection to `127.0.0.1:3389` as an additional local signal only.
- Queries RDP firewall rules by the language-independent group `@FirewallAPI.dll,-28752`, not by a localized display name.
- Parses the PowerShell `Enabled` values explicitly: `1`/`True` = enabled; `0`/`False` = disabled; `2` = not configured (not enabled). Unexpected values are treated as unverifiable/error.
- RDP is considered confirmed enabled only when the registry value is `0`. An open local port alone does **not** offer the RDP repair.
- RDP verification requires registry `fDenyTSConnections=1` and a successful RDP firewall-rule query with no enabled rules. Registry and firewall evidence are reported separately.
- **Limitation:** A local port 3389 check does not prove external exposure. No external scanning or RDP protocol negotiation is performed.

### Sensitive Filenames
- Resolves the selected folder with `os.path.realpath(..., strict=True)` before authorizing traversal. If the path cannot be resolved or verified, the check returns an **Error** and does not walk the filesystem or report a zero-match OK.
- Resolves the protected roots obtained from `%SystemRoot%`, `%WINDIR%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramW6432%`, and `%ProgramData%` with the same canonical-path logic. A selected folder is rejected when its real path is a protected root or a real descendant of one.
- Rejects complete drive roots such as `C:\` and UNC share roots such as `\\server\share`. Complete drive roots and protected system roots are still rejected; `C:\WindowsBackup` is not confused with `C:\Windows`.
- Uses case-insensitive, separator-normalized comparisons with directory boundaries. Relative paths, `..`, mixed separators, and different path casing are resolved before comparison.
- A rejected or unresolvable selection is reported as an **Error** result explaining what happened. It is never presented as a successful zero-match audit, and the user can start another audit after correcting the selection.
- Walks the canonical authorized root with `os.walk(..., onerror=..., followlinks=False)`.
- For every descendant directory, checks `lstat` metadata for `FILE_ATTRIBUTE_REPARSE_POINT`, resolves the directory with `realpath`, and verifies that it remains inside the authorized root and outside protected roots. Symbolic links, junctions, and reparse-point directories are excluded rather than followed. This avoids escapes through Windows junctions even where `followlinks=False` alone may not cover every alias.
- Confirms that every directory yielded by `os.walk` remains inside the canonical root. A directory outside the authorized scope is skipped and the result becomes partial.
- Excludes directories such as `AppData`, `Windows`, `Program Files`, `ProgramData`, `node_modules`, `.git`, `.vs`, `__pycache__`, `temp`, and `tmp` by modifying `dirs[:]` in place. Exclusions inside a valid root are different from selecting a protected root directly.
- Matches keywords in **filenames only**; file contents are not opened.
- Uses `os.stat(..., follow_symlinks=False)` on files only to detect metadata/access errors. It does not modify, move, open, or delete files.
- Reports unreadable roots, traversal errors, out-of-scope directories, excluded links, and file access errors. If there are no matches but some elements could not be examined, the result is **Not Verifiable**, not a confirmed absence.
- **Limitations:** False positives are expected (for example, `password_requirements.txt`). Excluded directories and excluded links are intentionally not examined, so a directory containing them is reported as partially analyzed. A path can still change between validation and traversal (a residual TOCTOU window); Guardian reduces the risk with canonical validation and per-directory revalidation but does not claim to eliminate all filesystem races. The number of descendants inside an unreadable directory is not known, so only the number of failed directories/files is reported. `lstat`/`realpath`/`stat` calls add overhead on very large trees.

## Repair Actions
- Each repair shows its name, description, exact PowerShell command, possible adverse effects, and Administrator requirement.
- **Explicit per-action confirmation is required.** Rejecting one action does not prevent confirming another.
- Administrator rights are checked with the current Windows token. Protected actions are not executed without them, no elevation is attempted, and the action is recorded as **not executed due to permissions**, not as a Guardian failure.
- Repair type is selected by an explicit action identifier (`firewall_enable_all`, `rdp_disable`), not by searching command text.
- A command that ran but could not be verified is reported as **executed, not verified** or **executed, verification error**; it is never reported as verified.
- Microsoft Defender is not included in the repair batch and cannot be marked as repaired by a firewall or RDP action. There is no fallback command path for changing real-time protection.
- Repair history, including skipped and permission-blocked actions, is included in the PDF report.
- **RDP disable warning:** May interrupt active remote sessions and block legitimate remote access.

## PDF Report Contains
- Application name, generation time, and audit timestamp.
- The selected folder as the analysis scope, with a note that access/traversal errors mean the folder was not fully covered.
- Summary counts (OK / Findings / Not Verifiable / Errors).
- Per-check detail: name, status, evidence, and recommendation.
- **ACTIVACIÓN MANUAL DE MICROSOFT DEFENDER** when a Defender real-time protection finding is present: what was detected, why Guardian does not change it, the six manual steps, the instruction to run a new audit, and the note about Windows restrictions.
- Repair log: action, command, output, error, verification evidence, manual guidance when applicable, and result (verified, executed but not verified, verification error, failed, skipped, or not executed due to permissions).
- Sensitive filenames (limited to 50 entries).
- When a repair cycle exists, the report is split into **1. Initial state (before repair)**, **2. Correction actions**, and **3. Post-repair state (re-audit)**. If no re-audit was performed, the report says so instead of presenting the old state as resolved. The Defender manual guide remains if it was present in the initial state, including after a firewall or RDP repair.
- A privacy notice and a clear disclaimer that this is not a professional assessment.

> **Privacy:** PDF reports can contain local paths, filenames, or other user-identifying information. Review a report before sharing it.

## Testing & Validation

### A. Automated tests
The regression suite uses the standard library `unittest` and mocks for PowerShell/system checks. It also creates temporary files and, when the environment allows it, real symbolic links or directory junctions inside the temporary directory. It does not execute repairs or modify firewall, Microsoft Defender, RDP, or registry settings.

```bash
python -m py_compile Guardian.py test_guardian.py
python -m unittest -v
python -m pip check
git diff --check
```

The suite covers:
- Result-state color mapping, including `unverifiable`/`error` with `severity="info"` or `"high"`.
- Accessible filename trees, matches, exclusions, inaccessible roots, `os.walk(onerror=...)` errors, file access errors, and partial results.
- Canonical path resolution with `realpath`, protected-root rejection before `os.walk`/`os.stat`, protected descendants, drive roots, UNC share roots, `..`/mixed separators, case-insensitive comparisons, and similar-prefix paths such as `C:\WindowsBackup`.
- Real symbolic-link/junction rejection when a link resolves to `Windows` or `ProgramData`, and exclusion of descendant links that point outside the authorized tree or into a protected root.
- Out-of-scope directories yielded by a mocked `os.walk`, path-resolution failures, and safe failure before traversal.
- Recovery after a failed or unresolvable audit: the operation finalizes and a new audit can be started.
- Audit finalization, state reset between consecutive audits, failed-audit recovery, active-operation guards, and repair-history preservation.
- Explicit repair dispatch by action type, strict firewall/RDP verification, RDP repair only from registry-confirmed state, Administrator re-checks, skipped actions, and failed actions.
- Defender detection for active, disabled, timeout, and PowerShell-error states; Tamper Protection/antivirus/mode diagnostics; manual guidance in the UI; and the absence of any executable Defender repair or fallback command.
- Firewall and RDP repair actions remain available, and a firewall repair cannot mark a Defender finding as fixed.
- PDF generation with scope, all result states, repair states, initial/action/post-repair sections, no-reaudit wording, new-audit context reset, privacy notice, and valid PDF header/content checks.
- PDF representation of path-resolution errors and link-exclusion/partial results.
- Defender manual activation section in the PDF, including the six steps and restrictions note, persistence after a firewall repair, and no attribution of manual activation to Guardian.

**Automated result:** 87 tests run, 87 passed, 0 failed, 0 skipped in the development environment (Windows 11, Python 3.14.7).

### B. Manual checks reported by the user in the Windows 11 VM
The following checks were reported by the user as performed manually in the Windows 11 VM. They were not re-executed by this automated run and are not necessarily repeated after the latest commit.
- The application opens and its buttons work.
- Firewall, Defender, RDP, and filename states are detected.
- Firewall repair was tested, including activation when the firewall was disabled.
- Repairs require running as Administrator.
- RDP detection and disabling were tested.
- The scanner stays within the selected folder and does not modify files.
- Direct selection of a protected folder was corrected, and the user reported that the protection worked.
- A PDF was generated and checked for the initial state, the actions, and the post-repair state.

### C. Validation pending or not confirmed after the latest commit
- The new symbolic-link, junction, alternate-path, UNC, and out-of-scope-walk cases are covered by automated tests on a Windows 11 development host, but they have not been manually re-confirmed in the target VM after this commit.
- Manual Defender activation in Windows 11 (Spanish UI) using the six steps, followed by a new Guardian audit that detects the active state. This has not been confirmed with the current version.
- Real firewall and RDP repairs after these changes, followed by real post-repair verification.
- Real elevated and non-elevated GUI behavior.
- UI responsiveness during very large file scans.
- Final visual review of the generated PDF in a PDF viewer, including the repair-cycle sections and the new error/partial wording.
- Automated PowerShell checks use mocks; they do not prove the state of a real managed Windows system.

### Additional checks performed
| Check | Result |
|-------|--------|
| `python -m py_compile Guardian.py test_guardian.py` | Pass |
| `python -m unittest -v` | Pass — 87 tests |
| `python -m pip check` | Pass — no broken requirements |
| `git diff --check` | Pass — only LF-to-CRLF warnings |
| Automated PDF test generation | Pass — valid `%PDF-` file; scope, statuses, repair history, repair-cycle sections, Defender manual guide, privacy text, path errors, and link-exclusion wording checked |
| Automated protected-path and link tests | Pass — direct protected roots, `C:\Windows` junction, `ProgramData` junction, descendant external link, and similar-prefix path checked |

> No firewall, Microsoft Defender, registry, or RDP setting was changed during validation. Repair behavior was exercised with mocked PowerShell responses only. The filename tests use temporary directories and, where available, temporary links/junctions; they do not scan real system folders. The manual checks in section B were reported by the user and were not re-executed by this automated run.

## Known Limitations
- Real repair verification depends on the same PowerShell/CIM providers used by the checks and has not been exercised against a real changed system state.
- Defender real-time protection is intentionally not modified by Guardian. It may be managed by Tamper Protection, Group Policy, another antivirus, or passive mode; Guardian reports these possibilities and manual guidance without bypassing them.
- Manual Defender activation must be validated in the target VM; the automated suite does not change real protection settings.
- PowerShell/CIM provider availability and permissions can vary between Windows editions and managed environments.
- The filename scan examines names, not content; it cannot confirm whether a file actually contains sensitive data.
- Excluded system/development directories and excluded symbolic links, junctions, or reparse-point directories are not scanned; inaccessible directories cannot be enumerated internally.
- Canonical validation and per-directory revalidation reduce path-alias risks, but a residual time-of-check/time-of-use window remains between validation and filesystem access.
- RDP checks are local only; they do not test external exposure or RDP negotiation.
- Large trees may take time because each filename is checked with `os.stat` and each directory is revalidated with `lstat`/`realpath`.
- The PDF layout has not been reviewed visually in every PDF viewer.

## Project Structure
```
guardian-pro-security-auditor/
├── Guardian.py       # Main application (UI + checks + PDF)
├── test_guardian.py  # unittest regression suite
├── README.md         # This file
├── LICENSE           # MIT license
├── requirements.txt  # Python dependencies
└── .gitignore        # Local artifacts and generated reports
```

## License
MIT — see [LICENSE](LICENSE).

## Author
Joaquín Porsella
