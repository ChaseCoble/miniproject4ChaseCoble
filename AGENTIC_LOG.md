# Agentic Workflow Log — Mini Project 4 (Track A, Vuln Hub)

Running record of prompts, actions, findings, and decisions made while
working with Claude Code on this pentest, per the logging practice added
to `CLAUDE.md`. Entries are appended in chronological order and are not
edited after the fact — corrections get a new entry.

---

## Entry 1 — 2026-10-10 — Route recon

**User prompt:** "Lets start with recon on the routes. What routes are
available? Start with what is linked and then run through the typical
targets."

**Actions taken (Claude):**
- Fetched `/` and enumerated the linked nav routes: `/`, `/login`,
  `/messages`, `/guestbook`, `/download?file=welcome.txt`.
- Probed typical/unlinked targets via `curl` status checks: `/robots.txt`,
  `/vault`, `/admin`, `/logout`, `/register`, `/api`, `/static/style.css`,
  `/favicon.ico`, `/sitemap.xml`, `/.git/config`, `/messages/1`, `/users`,
  `/profile`.
- Pulled `/robots.txt` content, inspected redirect `Location` headers for
  the 302s, and checked response headers on `/`.
- Logged in as the provided test account (`alice / password123`) to
  observe the authenticated flow: `/dashboard`, `/vault` (as a non-admin),
  and the `auth` session cookie.
- Decoded the `auth` cookie (`YWxpY2U6dXNlcg==` → `alice:user`) to
  understand the session mechanism.
- While mapping the numeric ID space of `/messages/<id>`, requested
  `/messages/1` (outside alice's own message range of #4–#5) to check for
  an ownership/access check.

**Findings:**
- Full route inventory documented (linked nav + probed targets); see
  summary table delivered to the user in this turn.
- `/robots.txt` discloses `Disallow: /backups/` — a filesystem path with
  no direct web route (404s on its own), strongly suggesting it's the
  target of the `/download?file=` path-traversal challenge.
- Session auth is an unsigned base64 blob of `username:role`
  (`auth=YWxpY2U6dXNlcg==` → `alice:user`), no HMAC/signature. `/vault`
  explicitly hints this: "The app decides your role from the `auth`
  cookie it handed you. How is that cookie built?" — points at the
  broken-authorization challenge.
- **`/messages/<id>` has no ownership check.** `GET /messages/1` as
  alice (who owns #4/#5) returned HTTP 200 with another user's private
  message:
  > `#1 — Onboarding secret` / `To: admin` / "Internal only. Do not
  > share. `FLAG{idor_407e97ee190c}`"
  This is the IDOR flag, captured incidentally during recon rather than
  as a deliberate exploitation step.

**Decisions / next steps (pending user confirmation):**
- Treat `FLAG{idor_407e97ee190c}` as captured but **not yet written to
  `submission.txt`** until the PoC for it is formally written up (per
  grading rule: a flag only counts with its PoC).
- Proposed next target: SQL injection on the `/login` form (hinted by
  the homepage: "the login form trusts what you type a little too
  much").
- Remaining untouched challenges after this entry: SQLi (login), stored
  XSS (guestbook), broken authz (`/vault` via the `auth` cookie), path
  traversal (`/download?file=`, likely targeting `/backups/`).

---

## Entry 2 — 2026-10-10 — Establish this log

**User prompt:** "Ensure the last interaction is recorded in a running
log of our interactions. Refer to CLAUDE.md on practices."

**Actions taken (Claude):**
- Read the updated `CLAUDE.md`, which now requires recording a running
  document of decisions/findings between user and Claude on confirmation
  of a finding or decision, to serve as agentic-workflow evidence for
  the assignment deliverables.
- Checked the project directory for an existing log (none found) and
  created this file, `AGENTIC_LOG.md`, backfilling Entry 1 for the route
  recon turn.

**Decisions:** This file is now the running log going forward; future
turns get a new dated entry each time a finding or decision is
confirmed.

---

## Entry 3 — 2026-10-10 — Create submission.txt

**User prompt:** "Create and update the submissions.txt required about
the assignment."

**Actions taken (Claude):**
- Checked for an existing `check_flags.py` / submission file in this
  repo — none present yet (starter files not yet copied in).
- Noted a naming mismatch: `CLAUDE.md`'s project section says
  `submissions.txt` (plural), but `asst.md` and `README.md` both specify
  `submission.txt` (singular) — the exact name `check_flags.py` expects
  (`python check_flags.py submission.txt --username <handle>`). Flagged
  this to the user and proceeded with `submission.txt` to match what
  the grader will actually read.
- Created `submission.txt` with the one flag captured so far,
  `FLAG{idor_407e97ee190c}` (the `/messages/1` IDOR from Entry 1), since
  the exploit step that produced it is already reproducible
  (`GET /messages/1` with alice's session cookie, documented in Entry 1).

**Findings:** No other flags captured yet — SQLi, stored XSS, broken
authz, and path traversal are still outstanding.

**Decisions / next steps:**
- `submission.txt` will be updated (one flag per line) as each
  additional flag is captured.
- Remember that credit for a flag in `submission.txt` depends on the
  pentest report containing a PoC for it — the report PoC section still
  needs to be written for the IDOR flag before this counts for points.
- Should flag the `submission.txt` vs `submissions.txt` naming
  discrepancy to the instructor per the user's own CLAUDE.md practice
  ("tell your instructor" pattern used elsewhere in the assignment).

---

## Entry 4 — 2026-10-10 — Login SQL injection + user dump

**User prompt:** "Yes, attempt the SQLI with a user dump."

**Actions taken (Claude):**
- Tested classic comment-based auth-bypass payloads against `POST
  /login`: `username=admin' -- ` and `username=' OR '1'='1' -- `
  (password field arbitrary). Both returned `302 → /dashboard` with a
  new `auth` cookie, vs. a `200` + "Invalid credentials" control for a
  genuine bad login.
- Decoded the resulting cookie (`YWRtaW46YWRtaW4=` → `admin:admin`) and
  fetched `/dashboard`, which revealed the SQLi flag in admin's private
  note: `FLAG{sqli_e845a880e16c}`.
- Checked `/vault` with the forged admin session — still `403`, role is
  `admin` not `superadmin`, confirming the vault challenge is separate
  from this one.
- Fingerprinted the UNION column count by submitting `' UNION SELECT
  1,2,3 -- ` etc. as username; 3 columns succeeded (302), others
  returned 200/error. Confirmed cookie mapping is built from columns
  2 and 3 of the result row (`username:role`), column 1 unused by the
  cookie.
- Used that reflection channel to enumerate the schema in-band (values
  placed in the username slot, read back via `/dashboard`'s "Signed in
  as" line):
  - Tables: `UNION SELECT 1, (SELECT group_concat(name) FROM
    sqlite_master WHERE type='table'), 3 -- ` → `users, messages,
    comments`.
  - `users` columns: `UNION SELECT 1, (SELECT group_concat(name) FROM
    pragma_table_info('users')), 3 -- ` → `id, username, password,
    role, secret_note`.
  - Full table dump: `UNION SELECT 1, (SELECT group_concat(id||'|'||
    username||'|'||password||'|'||role||'|'||secret_note, char(10))
    FROM users), 3 -- `.

**Findings:**
- **Confirmed SQL injection** in the `/login` username field — the
  query is string-built, not parameterized, and the WHERE clause is
  fully attacker-controlled via UNION.
- Full `users` table dumped (3 rows):
  | id | username | password | role | secret_note |
  |---|---|---|---|---|
  | 1 | admin | `mDIpCq0ixSUa65leZw3GNQ` (not obviously plaintext) | admin | contains `FLAG{sqli_e845a880e16c}` |
  | 2 | alice | `password123` (plaintext) | user | — |
  | 3 | bob | `qwerty2024` (plaintext) | user | — |
- No new/distinct flag surfaced in the dump beyond the one already
  captured via the auth-bypass step — same `FLAG{sqli_e845a880e16c}`,
  just re-observed via a different extraction technique.
- Secondary finding worth including in the report: **alice's and bob's
  passwords are stored in plaintext** (sensitive-data exposure,
  compounding the SQLi impact).
- **No `superadmin` user exists in the database at all.** Only
  admin/alice/bob, roles `admin`/`user`/`user`. This confirms the
  `/vault` challenge (#4) is about forging the unsigned `auth` cookie
  to claim a role that no real account has — not about finding a
  superadmin account via SQLi.

**Decisions / next steps:**
- Added `FLAG{sqli_e845a880e16c}` to `submission.txt` (now 2 flags) —
  PoC is reproducible and documented above.
- Next logical target: `/vault` broken authorization, via forging the
  `auth` cookie (e.g. base64 of `x:superadmin`) now that the cookie
  format is fully understood from this entry's column-mapping test.
- Remaining outstanding: stored XSS (guestbook), path traversal
  (`/download`), broken authz (`/vault`).

---

## Entry 5 — 2026-10-10 — /vault broken authorization via forged cookie

**User prompt:** "Go straight at /vault with the forged cookie."

**Actions taken (Claude):**
- Built a cookie value from scratch, with no login step at all:
  `base64("x:superadmin")` = `eDpzdXBlcmFkbWlu`, using the
  `username:role` format reverse-engineered in Entry 4's column-mapping
  test.
- Sent `GET /vault` with `Cookie: auth=eDpzdXBlcmFkbWlu` directly (no
  prior `/login` request, no real account named "x").

**Findings:**
- **Confirmed broken authorization / forgeable session.** The server
  returned `200 OK`, "Access granted, superadmin." and
  `FLAG{authz_fbd5823a9865}`.
- The `auth` cookie has **no signature, HMAC, or server-side session
  store backing it** — it is trusted as presented. Any client can set
  any `username:role` pair, including roles that don't correspond to
  any real database row (recall from Entry 4: no `superadmin` row
  exists in `users` at all — the role is purely a client-asserted
  string).
- This is a strictly stronger bypass than the SQLi: no credentials, no
  injection, no prior request to `/login` needed — just setting a
  cookie header.

**Decisions / next steps:**
- Added `FLAG{authz_fbd5823a9865}` to `submission.txt` (now 3 flags:
  IDOR, SQLi, broken authz). PoC is a single `curl` command, fully
  reproducible.
- Remaining outstanding: stored XSS (guestbook), path traversal
  (`/download`, likely targeting `/backups/` per Entry 1's robots.txt
  finding).

---

## Entry 6 — 2026-10-10 — check_flags.py added; validated progress

**User prompt:** "I just added the check_flags.py file to the
directory."

**Actions taken (Claude):**
- Read `check_flags.py` to understand it before running it (per
  CLAUDE.md: don't fabricate/guess tool behavior).
- Ran `python3 check_flags.py submission.txt --username clcoble`
  (FHSU username derived from the user's known email,
  clcoble@mail.fhsu.edu, used only for this identification purpose).

**Findings:**
- All 3 captured flags are **VALID** for seed `clcoble` — idor, sqli,
  authz. No "DEFAULT seed" warning, confirming Vuln Hub is running
  with the correct `FLAG_SEED` for this recon.
- Script source reveals the 6 challenge categories by name: `sqli,
  idor, xss, authz, traversal, exposure`. This confirms **"traversal"
  and "exposure" are two distinct flags**, not one combined
  challenge — `/download` path traversal and the `/robots.txt` →
  `/backups/` lead are likely separate exploitation steps even though
  related.

**Decisions / next steps:**
- 3/6 confirmed valid; remaining targets to attempt: `xss` (guestbook),
  `traversal` (`/download?file=`), `exposure` (likely via `/backups/`,
  possibly reached through the traversal bug itself but scored as a
  separate flag).
