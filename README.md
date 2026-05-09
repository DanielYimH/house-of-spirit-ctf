# House of Spirit — CTF Challenge

A CTF challenge and exploit demonstrating the **House of Spirit** heap exploitation technique targeting glibc 2.42 (tcache).

## Files

- `hos_challenge.c` — Vulnerable C binary
- `solve.py` — Full pwntools exploit

## Build

```bash
gcc -no-pie -fno-stack-protector -O2 -o hos_challenge hos_challenge.c
echo "flag{test_flag}" > flag.txt
```

## Attack Chain

1. Leak `print_flag` address, fake chunk address, and saved RIP location via the debug menu
2. Allocate a heap item with size `0x1a0` (416 bytes) — falls into the `0x1b1` tcache bin
3. Redirect the item's data pointer to the stack fake chunk via advanced edit
4. `free()` the fake stack address — House of Spirit places it into tcache
5. `malloc(0x1a0)` pops the fake chunk from tcache — we now own the stack
6. Write padding up to the saved RIP offset, then overwrite with `print_flag` address
7. Exit — main returns to `print_flag()` and prints the flag

## Requirements

- pwntools: `pip install pwntools`
- glibc 2.42

## License

MIT
