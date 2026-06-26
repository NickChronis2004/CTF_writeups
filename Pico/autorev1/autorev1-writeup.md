# Autorev 1 — picoCTF (Reverse Engineering, Medium)

## Overview

The server sends 20 ELF binaries one after another, each containing a hardcoded secret integer. You have 1 second per binary to extract the secret and send it back. Manual analysis is impossible — this requires automated binary analysis via scripting.

## Analysis

### Understanding the binary structure

Each binary is a simple C program that:
1. Stores a secret value in a local variable
2. Reads user input with `scanf`
3. Compares input to the secret
4. Prints "Correct!" or "Nice try :("

The relevant assembly in `main`:

```nasm
c7 45 fc 2f ca 2b 17    mov dword [rbp-4], 0x172bca2f
```

The opcode `c7 45 fc` (mov dword to [rbp-4]) is constant across all binaries — only the 4-byte immediate value changes. This is the secret.

### Extraction method

1. Receive the hex-encoded binary from the server
2. Search for the byte pattern `\xc7\x45\xfc` (mov dword [rbp-4])
3. Read the next 4 bytes as a little-endian unsigned 32-bit integer
4. Send it back as decimal

## Exploit

```python
import socket
import struct

s = socket.socket()
s.connect(('mysterious-sea.picoctf.net', 53754))

buf = b''
def recv_until(marker):
    global buf
    while marker not in buf:
        buf += s.recv(4096)
    idx = buf.index(marker) + len(marker)
    result = buf[:idx]
    buf = buf[idx:]
    return result

for i in range(20):
    recv_until(b"Here's the next binary in bytes:\n")
    data = recv_until(b"What's the secret?:")
    hex_str = data.split(b"What's the secret?:")[0].strip().decode()
    hex_str = hex_str.replace('\n', '').replace(' ', '')
    if len(hex_str) % 2 != 0:
        hex_str = hex_str[:-1]
    binary = bytes.fromhex(hex_str)
    idx = binary.find(b'\xc7\x45\xfc')
    secret = struct.unpack('<I', binary[idx+3:idx+7])[0]
    s.sendall(str(secret).encode() + b'\n')
    print(f"Binary {i+1}: {secret}")

rest = s.recv(4096)
print(rest.decode())
```

```
$ python3 solve.py
Binary 1: 3330071159
Binary 2: 988584667
...
Binary 20: 1539984140
Correct!
Woah, how'd you do that??
Here's your flag: picoCTF{4u7o_r3v_g0_brrr_78c345aa}
```

## Tools used

- `python3` with `socket` and `struct` — network communication and binary parsing
- Pattern matching on raw bytes — no disassembler needed

## Key takeaway

Automated reverse engineering is about finding invariant patterns across binaries. The compiler produces consistent opcode sequences for the same source code structure, so a simple byte pattern search can extract hardcoded values without full disassembly. This technique scales to hundreds of binaries in seconds.
