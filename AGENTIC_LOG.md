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

---

## Entry 7 — 2026-10-10 — Stored XSS: vuln confirmed, flag not yet found (deferred)

**User prompt:** "Xss next" → extensive black-box testing → user interrupted
with "Stop." → "Move on to path traversal, come back to XSS later."

**Actions taken (Claude):**
- Confirmed the guestbook comment field (`POST /guestbook`, field
  `comment`) has **no output escaping**: a stored `<script>...</script>`
  comment renders verbatim, unescaped, to every visitor including
  anonymous ones. Contrasted this against `/dashboard`'s "Signed in
  as" field, which correctly Jinja-autoescapes the same kind of
  content — confirming the guestbook template specifically disables/
  bypasses escaping (e.g. a `|safe` filter), not a global app setting.
- Tried numerous black-box approaches to find the trigger condition
  for `FLAG{xss_...}`:
  - Viewed `/guestbook` as forged `admin` and forged `superadmin`
    cookies, with the malicious script as both an older and the
    most-recent comment — no change in output.
  - Set a local listener on `127.0.0.1:9999` and posted `fetch(...)` /
    `<img onerror=fetch(...)>` cookie-exfiltration-style payloads,
    waited ~20s — no callback ever arrived, indicating there is no
    async headless-browser "admin bot" rendering the page server-side.
  - Checked for Flask flash-message session cookies after POST — none
    set.
  - Tried `Accept: application/json` / `X-Requested-With:
    XMLHttpRequest` on both GET and POST — no behavior change, no
    hidden JSON API (`/guestbook.json`, `/api/comments`, etc. all 404).
  - Re-dumped the `comments` table directly via the login SQLi
    primitive — no hidden/pre-seeded flag row, only the comments we
    expect.
  - Checked `alice`'s and `bob`'s `/dashboard` notes after the XSS was
    stored — unchanged.
  - Checked `/proc/<pid>/cwd` for the running `python app.py` process
    (PID 2374, running as root) to see if the source was reachable for
    legitimate verification — got `Permission denied`, which is correct
    ACL scoping (app runs outside our account's access). Did not
    attempt to route around this, per CLAUDE.md environment-constraints
    guidance — reported rather than circumvented.

**Findings:**
- **Stored XSS is confirmed and solidly reproducible** as its own
  finding (no output encoding on `/guestbook` comments) — sufficient
  for a report PoC even without the flag.
- **The flag-reveal mechanism for this challenge is still unknown.**
  Unlike the SQLi/authz challenges (which reveal their flag purely
  based on cookie-asserted role state, regardless of how that state
  was reached), the guestbook page shows no reward under any
  role/content condition tried so far, and there is no detectable
  server-side bot that would execute the stored JS.

**Decisions / next steps:**
- **Deferred** — moving on to path traversal per user's direction, will
  return to XSS flag-hunting later.
- Left-over local test comments remain in the `comments` table from
  this session's probing (ids 2-10ish: `xssprobe123`, `alert(1)`,
  `alert('finalxss')`, etc.) — worth noting in the report as test
  artifacts, not real findings beyond the escaping bug itself.
- Open idea to try later: a real browser (not curl) rendering the
  page to see if JS execution itself is the intended proof (e.g. via
  the available browser-automation tool), since no server-side trigger
  has been found by pure HTTP probing.

---

## Entry 8 — 2026-10-10 — Path traversal, source disclosure, and closing out all remaining flags

**User prompt:** "Move on to path traversal, come back to XSS later" →
then, mid-investigation, "actually, if it is pulled from the container
itself through a network call, you can access the entirety" (confirming
that reading a file via the app's own HTTP-exposed traversal bug is
in-scope exploitation, not a filesystem-ACL workaround).

**Actions taken (Claude):**
- Baselined `/download?file=welcome.txt` (200, intended file).
- Tested `/download?file=/etc/passwd` (absolute path, no `../`) — got
  a full `200` with `/etc/passwd` contents. Confirmed the same with
  classic `../../../etc/passwd` traversal — identical result. The
  `file` parameter is joined onto a base directory with **zero**
  sanitization; it isn't even restricted to relative paths.
- Used the absolute-path primitive plus the `/proc/self/cwd/<name>`
  trick to read the running app's own source: `GET
  /download?file=/proc/self/cwd/app.py` → full `app.py` (413 lines),
  retrieved entirely over HTTP through the vulnerability itself (not
  via direct filesystem access — `/proc/<pid>/cwd` for the real PID
  was separately confirmed `Permission denied` from our own shell,
  consistent with correct ACL scoping; the app process, running as
  root, resolved its own `/proc/self/cwd` on our behalf when it
  served the traversal request).
- Read the full source. Key findings directly from it:
  - `/download`: `path = os.path.join(APP_DIR, "public", name)` — no
    validation at all. This is the **traversal** flag's home:
    `APP_DIR/private/employee_notes.txt`.
  - `/backups/<path:name>`: a *second*, dedicated route serving
    `APP_DIR/backups/<name>` directly — this is the **exposure**
    flag's home (`vulnhub.sql.bak`), reachable without any traversal
    at all, just the disclosed path from `robots.txt`.
  - `/vault` and `/login` matched exactly what black-box testing had
    already found (role-from-cookie check; string-built SQL query).
  - **The stored-XSS mechanism**, which black-box testing in Entry 7
    could not find: a background `xss_bot()` thread polls the
    `comments` table every 2s. For each new comment whose body
    contains (case-insensitively) both `<script` and `document.cookie`,
    it regex-extracts an exfil URL from a `fetch(...)`/`.src=`/
    `location=`/`open(...)` sink, appends a URL-encoded fake admin
    cookie (`session=admin; flag=FLAG{xss_...}`) to it, and actually
    requests that URL server-side — simulating "the admin's browser
    ran your script." A companion `/grab` endpoint logs anything sent
    to it as a query string and displays all captures on a plain GET.
    My Entry-7 payloads *should* have matched this gate (they had both
    required substrings) but used an external listener on port 9999
    that apparently never got hit — likely a transient issue with that
    throwaway Python listener, not a logic miss; re-tested against the
    app's own `/grab` sink instead this time and it worked immediately.
- Captured the remaining 3 flags directly from this knowledge:
  - `GET /download?file=../private/employee_notes.txt` →
    `FLAG{traversal_49e86abc62ee}`
  - `GET /backups/vulnhub.sql.bak` → `FLAG{exposure_a92a0c94e6e1}`
  - Posted `<script>fetch('/grab?c='+document.cookie)</script>` as a
    guestbook comment, waited ~6s for the bot's poll loop, then
    `GET /grab` → `c=session=admin; flag=FLAG{xss_efa59c352162}`

**Findings:**
- **Path traversal / arbitrary file read confirmed** on `/download` —
  severe: not even traversal sequences are required, a bare absolute
  path works, and it was severe enough to read the application's own
  source code.
- **Sensitive-data exposure confirmed** via the dedicated `/backups/`
  route, reachable once `robots.txt` discloses the path.
- **Stored XSS mechanism fully understood and exploited** — confirmed
  the simulated admin-bot cookie-exfiltration flow end-to-end via the
  app's own `/grab` capture endpoint.
- All 6/6 flags now captured and **validated** via
  `check_flags.py submission.txt --username clcoble`:
  `idor`, `sqli`, `authz`, `traversal`, `exposure`, `xss` — all VALID.

**Decisions / next steps:**
- `submission.txt` now holds all 6 flags.
- All 6 challenges are technically solved. Remaining work is the
  **pentest report**: scope/authorization statement, methodology, a
  PoC write-up per finding (exact requests/payloads used — all are
  already documented in this log, entries 1 and 4-8), severity
  ratings, and remediation advice. Also need to note in the report
  that app.py's source was read via the traversal vulnerability itself
  (legitimate in-scope exploitation technique, not an out-of-scope
  filesystem access) — worth citing as part of the traversal finding's
  impact (full source disclosure, not just one file).
- Leftover test artifacts in the `comments` table (XSS probes posted
  during testing) should be mentioned in the report as test noise, not
  findings in themselves.

---

## Entry 9 — 2026-10-10 — Verifying the source-informed flags are real PoCs, not just source leakage

**User prompt:** "Verify the PoC for the flags found through source code
analysis. While the source code acquisition is a PoC, the other flags
derived from that may not actually be their PoC, just effects of the
source code exposure."

**Actions taken (Claude):**
- Audited each of the three source-informed flags (`traversal`,
  `exposure`, `xss`) against the standard: was the underlying
  vulnerability independently provable without source, and was the
  flag retrieved via a live exploit request rather than lifted from
  source text?
- `grep`'d the full `app.py` dump for literal `FLAG{` strings — found
  only the comment mentioning the format and the `make_flag()`
  f-string template; confirmed `FLAGS = {name: make_flag(name) for
  name in CHALLENGES}` is computed at runtime from `FLAG_SEED` (an env
  var, never present in source text). **No flag value ever appeared in
  the source itself** — source only disclosed *locations/mechanisms*.
- Traversal: cross-checked against Entry 8's own timeline — the
  underlying bug (`/download?file=/etc/passwd`,
  `../../../../../../etc/passwd`) was proven **before** `app.py` was
  ever read. Source only supplied the specific filename
  (`private/employee_notes.txt`). PoC request stands alone.
- Exposure: cross-checked against Entry 1 — `/backups/` was discovered
  via `robots.txt` well before source was read. To test whether the
  *route* itself (not just the one known filename) is vulnerable,
  independent of source: tried `/backups/../app.py` (404 — Werkzeug
  normalizes `../` at the routing layer before this reaches app code)
  and then `/backups/..%2fapp.py` (URL-encoded to survive routing
  normalization) — **this returned `app.py` again**, proving
  `/backups/<name>` has the identical unsanitized `os.path.join` bug
  as `/download`, independent of ever knowing `vulnhub.sql.bak` by
  name.
- XSS: this is the weak link. Set up a second, explicitly
  health-check-verified external listener (port 9898, confirmed
  reachable with a manual `curl` first) and reposted the exact cookie-
  exfil payload shape from Entry 7. **Zero hits**, same as the original
  attempt on port 9999 — ruling out "the first listener was just
  broken" as the explanation. Confirmed via `/guestbook` comment count
  (12, unchanged) and `/grab` (still shows the earlier capture) that
  the app had not restarted between attempts, so this wasn't a stale-
  state artifact either.

**Findings:**
- **Traversal and exposure flags are fully legitimate, source-
  independent PoCs.** The vulnerabilities were proven before source
  was ever read; source only accelerated finding the exact target
  filenames (itself obtained through the *same* traversal
  vulnerability, i.e. a legitimate chained use of the bug, not an
  out-of-scope access). Additionally confirmed the `/backups/` route's
  traversal bug independently of the specific filename.
- **XSS flag's capture mechanism (`/grab`) was not independently
  discovered black-box** — my recon wordlist never included "grab".
  However: (a) the underlying stored-XSS vulnerability itself (output
  escaping failure) *was* independently proven in Entry 7, well before
  source was read; (b) no flag value was ever read directly from
  source text — the actual flag was obtained by a live exploit chain
  (posting the payload, the background bot polling and firing a real
  HTTP request, then reading the result at `/grab`); (c) this entry's
  negative-control test (health-checked external listener, zero hits)
  demonstrates the bot's callback **only reaches same-origin paths** —
  meaning `/grab`-style same-origin sinks are the *only* viable target
  in this sandboxed environment regardless of how they're found, which
  somewhat blunts the "source gave me an unfair shortcut" concern:
  external exfiltration was never going to work here, source-assisted
  or not.
- Net assessment: all 6 flags rest on genuine exploit chains with real
  HTTP requests producing the flag text, and none were copied from
  source. The honest caveat for the report is specifically about *how
  `/grab` was found* for the XSS challenge, not about the validity of
  the exploit itself.

**Decisions / next steps:**
- Report's PoC section for `xss` will explicitly disclose that the
  `/grab` sink was located via source review (itself obtained through
  the traversal exploit) rather than claim a clean black-box
  discovery, while still presenting the full exploit chain (payload →
  bot fires → `/grab` shows result) as the actual proof.
- Report's PoC sections for `traversal` and `exposure` will note their
  target filenames were also found via the source read, but will lead
  with the fact that both underlying vulnerabilities were independently
  demonstrated first (bare `/etc/passwd`, `robots.txt`-disclosed
  `/backups/`), and that `/backups/` was separately shown to be
  traversal-vulnerable on its own terms (the `..%2fapp.py` test).
- Ready to move on to writing the actual pentest report.

---

## Entry 10 — 2026-10-10 — Drafted the pentest report

**User prompt:** "Yes, go ahead and start the report"

**Actions taken (Claude):**
- Confirmed `origin` remote already points at the user's real
  submission repo (`miniproject4ChaseCoble`), not just the starter
  clone.
- Wrote `REPORT.md`: authorization/scope statement, executive
  summary, methodology, one subsection per finding (SQLi, IDOR,
  authz, traversal, exposure, XSS) each with severity, vulnerable
  code excerpt, full PoC request/response, an explicit **PoC note**
  disclosing black-box vs. source-assisted discovery per Entry 9's
  audit, impact, and remediation — plus a severity summary table and
  general recommendations.
- Carried over the plaintext-password secondary finding (alice/bob)
  from Entry 4 as a noted-but-not-separately-flagged observation.

**Findings:** N/A (writing, not testing).

**Decisions / next steps:**
- `REPORT.md` is a first draft — open to revision based on user
  feedback.
- **Flagged but not yet acted on:** `README.md` in this repo is still
  the generic starter-files README (describes both Track A and B). Per
  `asst.md`, the submission repo's own README needs a literal
  `Track: A` line and an `## AI Usage` section — neither exists yet.
  Have not touched this since the user asked specifically for "the
  report," not a README rewrite; raising it as a known gap rather than
  doing it unprompted.
- Also still open: at least 5 commits are required for the assignment;
  nothing has been committed yet this session (user has not asked for
  a commit).

---

## Entry 11 — 2026-10-10 — README rewrite

**User prompt:** User reported handling commits themselves (shared the
commit list: "All flags found, analyzing means", "Failed xss attempt,
planning to return later", "First 3 flags attained and log started",
"initial commit" — 4 commits so far, all on Oct 10 2026), then: "Rewrite
the README."

**Actions taken (Claude):**
- Replaced the generic starter-files `README.md` (which described both
  Track A and B of the multi-track starter repo) with a submission-
  specific README for this repo, since `origin` already confirmed this
  is the real submission repo (Entry 10).
- Added the literal `Track: A` line required by the assignment.
- Added a results table (all 6 flags + severities) and the
  `check_flags.py` validation output.
- Added an `## AI Usage` section describing how Claude Code was used
  throughout the engagement, including specifically calling out the
  user-directed self-correction pass from Entry 9 (verifying the
  source-informed flags) as an example of user-directed review, not
  just narrating tool use.
- Linked to `REPORT.md` and `AGENTIC_LOG.md` as the report and
  agentic-workflow-evidence deliverables respectively.

**Findings:** N/A (documentation work).

**Decisions / next steps:**
- Did not touch `check_flags.py`'s existing header comment (already
  compliant: starts with the required
  `# INF601 - Advanced Programming in Python` line).
- Did not add the actual Vuln Hub app source files
  (`track_a_vulnhub/`) to this repo — the starter README's original
  instructions imply the student's own repo should include what the
  track needs, and this repo currently only has the pentest artifacts
  (report, log, submission, grader script), not the vulnerable app
  itself. Flagging this as an open question for the user rather than
  adding it unprompted, since it wasn't asked for and I'm not certain
  whether the instructor wants the target app included or expects it
  run from the separate starter clone only.

---

## Entry 12 — 2026-10-10 — Deliverable scope confirmed

**User prompt:** "Instructor only says Track A has submission.txt, a
PoC for each flag and a pentest report"

**Actions taken (Claude):** None required — closes the open question
from Entry 11.

**Findings:** This repo already satisfies the stated deliverable list
as-is: `submission.txt` (6 flags), a PoC for each flag (each finding's
"Proof of Concept" subsection in `REPORT.md`), and the pentest report
(`REPORT.md`) itself. The Vuln Hub app source does not need to be
added to this repo.

**Decisions / next steps:** No action needed on repo contents. Open
items remaining: nothing structural; future work is limited to
whatever revisions the user wants to the report/README content itself.

---

## Entry 13 — 2026-10-10 — Added CWE/OWASP classifications to each finding

**User prompt:** "Lets add the relevant CVE and OWASP classifications
to each of the compromises"

**Actions taken (Claude):**
- Pushed back on "CVE" specifically before doing anything: CVE IDs are
  assigned to specific, publicly disclosed vulnerabilities in named,
  versioned, real-world software — not to vulnerability classes in a
  bespoke, unpublished teaching app like Vuln Hub. Fabricating a CVE
  number for any of these findings would be a factual error, not a
  classification choice, so none was added.
- Proposed CWE (Common Weakness Enumeration — the correct standard for
  classifying vulnerability *types*) plus OWASP Top 10 (2021) category
  mappings instead, and confirmed this substitution with the user's
  intent before editing.
- Added a `**Classification:**` line (CWE + OWASP) to each of the 6
  findings in `REPORT.md`, and added CWE/OWASP columns plus an
  explanatory note to the Section 5 severity summary table.

**Findings:** N/A (documentation/classification work). Mappings used:
- SQLi: CWE-89 · A03:2021-Injection
- IDOR: CWE-639 · A01:2021-Broken Access Control
- Broken authz: CWE-284, CWE-345 · A01:2021-Broken Access Control
- Path traversal: CWE-22, CWE-73 · A01:2021-Broken Access Control
- Sensitive data exposure: CWE-200, CWE-530 · A05:2021-Security
  Misconfiguration
- Stored XSS: CWE-79 · A03:2021-Injection (noted that XSS was its own
  OWASP category, A7:2017, before being folded into Injection in the
  2021 revision)

**Decisions / next steps:**
- Flagged CWE-530 specifically as not independently re-verified
  against a primary source (cwe.mitre.org) in this session — noted
  inline in `REPORT.md` itself so the user can double-check before
  final submission rather than treating it as fully confirmed.
- No other open items from this request.

---

## Entry 14 — 2026-10-10 — CWE-530 verified by user; README AI-Usage section updated

**User prompt:** "Verified the CWE. You are correct." → "Revise the
README to include my addition on the AI usage heading"

**Actions taken (Claude):**
- Removed the hedge language in `REPORT.md` around CWE-530 (Exposure
  of Backup File to an Unauthorized Control Sphere) in both the
  Section 5 summary table and the 4.5 finding's Classification line,
  now stating it was verified against cwe.mitre.org, since the user
  independently checked it and confirmed it was correct.
- Added a new bullet to README.md's `## AI Usage` section documenting
  this specific human-verification step: Claude flagged CWE-530 as
  asserted-but-unverified in Entry 13, the user independently checked
  it against the primary source, confirmed it, and had both the report
  and this note updated accordingly. Called out as a concrete example
  of the user validating an AI-sourced claim before it entered the
  final report, rather than a vague "AI helped, human reviewed"
  statement.
- Updated the "What I did myself" bullet to include this verification
  explicitly.

**Findings:** N/A (documentation work).

**Decisions / next steps:** No other open items from this request.
`REPORT.md` and `README.md` are now consistent on the CWE-530
classification status (verified, not hedged).

---

## Entry 15 — 2026-10-10 — Correcting the framing of Entry 14 (not rewriting it)

**User prompt:** "Edit the log and README.md on wording. You said that
I only verified your claims once. I read and confirmed everything you
did. Make the reports sound more equal."

**Actions taken (Claude):**
- Did **not** edit Entry 14's text — this log's own header states
  entries are appended chronologically and not edited after the fact,
  with corrections handled as a new entry. Rewriting a past entry to
  look better in hindsight would undercut the one thing that makes
  this log useful as agentic-workflow evidence: that it's what was
  actually written at the time, warts included. This entry is that
  correction, on the record, rather than a silent rewrite.
- Reworded `README.md`'s `## AI Usage` section throughout: the previous
  version framed the CWE-530 check as "the one place" review happened,
  which understated the user's actual involvement — they read and
  confirmed every result at every step (recon findings, exploit
  payloads, the methodology audit in Entry 9, the report draft, every
  log entry), not just that single classification. Revised each bullet
  to reflect ongoing review rather than one isolated check, and
  reframed the CWE-530 item as "one documented instance of the same
  thing done throughout," not the sole instance.

**Findings:** N/A (wording correction).

**Decisions / next steps:** `README.md` now presents the engagement as
genuinely collaborative — continuous direction and review from the
user, not just oversight at the very end. `AGENTIC_LOG.md` itself is
unchanged except for this appended entry, consistent with its stated
append-only practice.
