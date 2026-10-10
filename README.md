# INF601 Mini Project 4 — starter files

Mini Project 4 is an **agentic project**: you do real work driven by **Claude Code**,
then write a professional, AI-assisted report about it. There are two tracks.
**Pick the one that matches your concentration** (not sure? ask your instructor).

| Track | Who | What you do | Start here |
|---|---|---|---|
| **A — Vuln Hub** | Cybersecurity | Pentest a deliberately vulnerable Flask app on your own machine, capture 6 flags, write a pentest report | [`track_a_vulnhub/README.md`](track_a_vulnhub/README.md) |
| **B — Build Hub** | CS / other | Build a small data toolkit to a fixed spec, checked by hidden tests, write a technical report | [`track_b_buildhub/README.md`](track_b_buildhub/README.md) and [`SPEC.md`](track_b_buildhub/SPEC.md) |

**Due Sunday 11 October 2026, 23:59 Central.** Submit the link to your own GitHub repo
named `miniproject4YourFullName`. Do not submit this starter folder itself: copy what
your track needs into your own repo.

## 1. Say which track you did

Your own repo's `README.md` must contain a line that says exactly

```text
Track: A
```

or `Track: B`, on its own line. That line decides how your repo is graded.

## 2. Get your seeds

Your seeds come from your **FHSU username** (e.g. `jdoe`). They are not secret; they
just make each student's flags and graded parameters different. From the root of this
folder:

```bash
python my_seeds.py jdoe
```

It prints `FLAG_SEED=...` (Track A) and `BUILD_SEED=...` (Track B), plus the line to
set `FLAG_SEED` in bash/zsh and in Windows PowerShell. Use `python3` if `python` is
not found on macOS/Linux.

## 3. How credit works

- **Track A:** each flag counts **only if your report's Proof-of-Concept shows the
  exploit that produced it**. The flags also sit in plain files on your machine, so a
  flag without its exploit earns nothing. Run Vuln Hub with your own `FLAG_SEED`. If
  you captured flags while the app was on the **default seed** (red banner on every
  page), **tell your instructor** in your report: those count only with a PoC.
  `track_a_vulnhub/check_flags.py` tells you VALID / NOT VALID; it awards no points.
- **Track B:** a hidden autograder scores your `buildhub` out of 60 using your
  `BUILD_SEED`; the public tests in `starter/tests/public` are only a subset.
- Both tracks: the report, the agentic-workflow evidence (transcript or summary of how
  you directed Claude Code), an `## AI Usage` section in your README, and at least 5
  commits. Any `.py` file you submit starts with the header comment
  (`# INF601 - Advanced Programming in Python` / `# Your Name` / `# Mini Project 4`),
  and your repo is named `miniproject4YourFullName`. You must be able to explain every
  line at the Week 16 review.

## Safety (Track A)

Vuln Hub is **deliberately insecure**. Run it only on your own machine, bound to
`127.0.0.1` (the default). Never expose it to a network or the internet, and test
**nothing else** — only this app is in scope.
