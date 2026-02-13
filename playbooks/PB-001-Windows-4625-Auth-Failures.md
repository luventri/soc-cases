# PB-001 — Windows 4625 (Auth Failures)

## Objective
Triage and close cases for Windows failed logons (EventID 4625) with reproducible lab tests.

## Classification (MVP)
- **single**: low volume, usually 1 user, short burst.
- **brute force**: high volume against the same user in a short window.
- **spray**: multiple different users targeted in a short window.

## Verdict (MVP)
**FP** when:
- Expected lab test / user typo
- Source is localhost/internal lab and there is no escalation (no 4624 success after)

**TP** when:
- brute force or spray patterns
- Any correlated 4624 success for same user/IP in close time proximity
- Targets privileged/admin/service accounts

## Severity (MVP)
- **Low**: single + localhost/internal + no success
- **Medium**: brute force OR spray from localhost/internal
- **High**: spray from non-local source OR any success after failures

## Evidence to capture (minimum)
- Window start/end (from issue)
- Host: agent.name + agent.id
- Total failures + distinct users + top source IP
- Target user(s)
- LogonType
- Status/SubStatus

## Closure template
Between <start> and <end>, <pattern> 4625 failures were observed on <host>, targeting <N users> from <top IP>.
No correlated 4624 successes were found in the same window. Activity confirmed as <lab test / suspicious>. Closed as <FP/TP> (Severity: <Low/Medium/High>).

## Lab tests (safe)
A) Benign (FP expected): 3 failures (fake user)
PowerShell:
for ($i=1; $i -le 3; $i++) { cmd /c "runas /user:.\noexiste notepad.exe" | Out-Null }

B) Spray (TP expected): 8 users, 1 try each
PowerShell:
1..8 | % { cmd /c "runas /user:.\user$_ notepad.exe" | Out-Null }

C) Brute force (TP expected): 25 tries same user
PowerShell:
1..25 | % { cmd /c "runas /user:.\user1 notepad.exe" | Out-Null }
