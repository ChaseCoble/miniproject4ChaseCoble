# Mini Project 4 — Vuln Hub Penetration Test

Track: A

An authorized penetration test of **Vuln Hub**, the deliberately
vulnerable Flask application provided as the Track A target for
INF601 Mini Project 4. All six planted vulnerabilities were found and
exploited, with a unique flag captured and validated for each.

**Author:** Chase Coble (FHSU username: `clcoble`)

## Results

| Finding | Severity | Flag |
|---|---|---|
| SQL Injection (login bypass + full DB dump) | Critical | `FLAG{sqli_e845a880e16c}` |
| IDOR (private messages) | High | `FLAG{idor_407e97ee190c}` |
| Broken Authorization (forged session cookie) | Critical | `FLAG{authz_fbd5823a9865}` |
| Path Traversal (`/download`) | Critical | `FLAG{traversal_49e86abc62ee}` |
| Sensitive Data Exposure (`/backups/`) | High | `FLAG{exposure_a92a0c94e6e1}` |
| Stored XSS (guestbook) | Medium-High | `FLAG{xss_efa59c352162}` |

```
$ python check_flags.py submission.txt --username clcoble
...
6/6 flags valid for username clcoble
```

Full details — scope/authorization statement, methodology, a
proof-of-concept for every finding, impact, and remediation advice —
are in **[`REPORT.md`](REPORT.md)**.

## Repo contents

- **`REPORT.md`** — the pentest report (the actual deliverable).
- **`submission.txt`** — all six captured flags, one per line.
- **`AGENTIC_LOG.md`** — a complete, timestamped, prompt-by-prompt log
  of the agentic workflow with Claude Code: every action taken, every
  finding, every decision, including dead ends (e.g. failed XSS
  callback attempts) that were ruled out along the way. This is the
  agentic-workflow evidence for this submission.
- **`check_flags.py`** — the grader script provided with the
  assignment; checks `submission.txt` against the flags derived from
  `FLAG_SEED` (VALID/NOT VALID only, awards no points itself).
- **`CLAUDE.md`** — the project-specific Claude Code configuration and
  working-practices document used throughout this engagement
  (environment constraints, workflow rules, and the running-log
  practice that produced `AGENTIC_LOG.md`).
- **`asst.md`** — the original assignment prompt, kept for reference.

## Scope and ethics

Vuln Hub was run locally, bound to `127.0.0.1:5000`, with
`FLAG_SEED=clcoble`, and nothing else was tested. See `REPORT.md`
Section 1 for the full signed-style authorization and scope statement.

## AI Usage

This project was done with Claude Code (Opus 5 / Sonnet 5) driving the
hands-on recon and exploitation. I directed every step, read and
confirmed each result before moving to the next one, and made the
calls on what to pursue, when to push back, and when something needed
re-checking. This wasn't "launch it and collect the output" — every
request below, exploit, flag, and claim in the final report was
something I looked at and signed off on before it went in.

- **Recon and exploitation:** Claude Code ran all HTTP-level recon and
  exploitation (`curl`-driven route enumeration, SQL injection payload
  testing and UNION-based data extraction, cookie forging, path
  traversal probing, and the stored-XSS investigation) at my direction,
  one vulnerability at a time. I reviewed each result — the route map,
  the injection responses, the forged-cookie response, the traversal
  reads, the XSS behavior — before deciding the next move, chose the
  order of attack, and told it when to move on versus dig further.
- **Methodology audit I asked for:** after all six flags were
  captured, I specifically asked Claude to go back and verify that the
  three flags found with help from a source-code read (obtained itself
  through the path-traversal exploit) had PoCs that were genuinely
  the exploit that produced them, rather than just effects of having
  read the source. It re-tested each one, found that two were fully
  independent of the source read, and that the third (stored XSS) had
  a real but source-assisted discovery step — it disclosed that
  distinction plainly in the report rather than glossing over it. I
  read that audit and agreed with its conclusions before it went into
  the report. See `AGENTIC_LOG.md`, Entry 9.
- **Report drafting:** the first draft of `REPORT.md` was written by
  Claude Code from the session's own findings. I read it in full and
  confirmed the content before accepting it as the submission's report.
- **Running log:** I had Claude Code maintain `AGENTIC_LOG.md` as a
  running, append-only record of prompts/actions/findings/decisions
  throughout, per a practice I added to `CLAUDE.md` partway through
  the engagement — that file is the fullest record of the actual
  back-and-forth, and I reviewed each entry as it was added.
- **Classification review:** when Claude Code added CWE/OWASP
  classifications to each finding, it explicitly refused to invent CVE
  IDs (correctly — CVEs don't apply to a bespoke app like this) and
  flagged one mapping, CWE-530 for the backup-exposure finding, as
  asserted from memory but not independently re-verified against a
  primary source. I checked it myself against cwe.mitre.org, confirmed
  it was correct, and had both `REPORT.md` and this note updated
  accordingly. This is one concrete instance of the same thing I did
  throughout: reading and confirming the actual work rather than
  taking any of it at face value.
- **What I did myself:** directing the engagement end to end, reading
  and confirming every finding, PoC, and claim before it was accepted
  into the report (not only the CWE-530 check above — that one just
  happens to be documented explicitly), reviewing and committing
  everything, and all git history/commit messages.
